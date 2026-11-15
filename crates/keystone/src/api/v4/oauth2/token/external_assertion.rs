// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! External JWT subject-token exchange.

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cadf::Outcome;
use serde_json::Value;

use openstack_keystone_config::Oauth2Provider;
use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::oauth2_client::{
    SubjectTokenValidationProfile, verify_subject_token_jwt,
};
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::federation::IdentityProvider;
use openstack_keystone_core_types::oauth2_client::{Confirmation, OAuth2ClientResource};

use crate::audit::{build_initiator_from_vsc, emit_oauth2_session_event};
use crate::federation::api::oidc_utils;
use crate::keystone::ServiceState;

use super::exchange_request::ACCESS_TOKEN_TYPE;
use super::token_exchange::{requested_audience, subject_token_carries_cnf};
use super::{Oauth2TokenError, TokenForm, TokenResponse};

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_external_assertion_exchange(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    correlation_id: &str,
    form: &TokenForm,
    client: &OAuth2ClientResource,
    subject_token: String,
    confirmation: Option<Confirmation>,
    scope: String,
    oauth2_cfg: &Oauth2Provider,
) -> Result<Response, Oauth2TokenError> {
    handle_external_assertion_exchange_with_replay(
        state,
        domain_id,
        headers,
        correlation_id,
        form,
        client,
        subject_token,
        confirmation,
        scope,
        oauth2_cfg,
        &ReplayProtectionUnavailable,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_external_assertion_exchange_with_replay(
    state: &ServiceState,
    domain_id: &str,
    headers: &HeaderMap,
    correlation_id: &str,
    form: &TokenForm,
    client: &OAuth2ClientResource,
    subject_token: String,
    confirmation: Option<Confirmation>,
    scope: String,
    oauth2_cfg: &Oauth2Provider,
    replay_protection: &dyn AssertionReplayProtection,
) -> Result<Response, Oauth2TokenError> {
    let unverified_issuer = extract_unverified_issuer(&subject_token)
        .ok_or_else(|| Oauth2TokenError::invalid_grant("subject_token is not a valid JWT"))?;
    let exec = ExecutionContext::internal(state);
    let idp = state
        .provider
        .get_federation_provider()
        .get_identity_provider_by_issuer(&exec, domain_id, &unverified_issuer)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "external assertion issuer lookup failed");
            Oauth2TokenError::internal("subject_token validation failed")
        })?
        .ok_or_else(|| Oauth2TokenError::invalid_grant("subject_token issuer is not trusted"))?;

    let jwks = load_identity_provider_jwks(&idp).await?;
    let base = crate::api::v4::oauth2::well_known::base_url(state, headers).await;
    let token_endpoint_audience = format!("{base}/v4/oauth2/{domain_id}/token");
    let profile = SubjectTokenValidationProfile::external_assertion(
        std::slice::from_ref(&unverified_issuer),
        &token_endpoint_audience,
    );
    let verified_claims: Value = verify_subject_token_jwt(&subject_token, &jwks, &profile)
        .map_err(|error| {
            tracing::warn!(error = %error, "external assertion rejected");
            Oauth2TokenError::invalid_grant(
                "subject_token is invalid, expired, or has invalid claims",
            )
        })?;

    if subject_token_carries_cnf(&subject_token) {
        return Err(Oauth2TokenError::invalid_request(
            "a DPoP-bound subject_token cannot be exchanged",
        ));
    }

    let assertion_exp = verified_claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| Oauth2TokenError::invalid_grant("subject_token has no valid expiry"))?;
    let assertion_jti = verified_claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= 256)
        .ok_or_else(|| Oauth2TokenError::invalid_grant("subject_token has no valid jti"))?;

    replay_protection
        .check_and_record(domain_id, &unverified_issuer, assertion_jti, assertion_exp)
        .await
        .map_err(map_replay_protection_error)?;

    let subject = verified_claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| Oauth2TokenError::invalid_grant("subject_token has no valid subject"))?;
    let flattened = crate::federation::api::common::flatten_federation_claims(&verified_claims)
        .map_err(|error| {
            tracing::warn!(error = %error, "external assertion claims could not be mapped");
            Oauth2TokenError::invalid_grant("subject_token claims could not be mapped")
        })?;
    let (vsc, ruleset_version) =
        openstack_keystone_core::oauth2_client::hydrate_external_assertion_context(
            state,
            domain_id,
            &unverified_issuer,
            subject,
            flattened,
        )
        .await
        .map_err(map_mapping_error)?;

    let audience = requested_audience(state, &form.audience).await?;
    let issuer = format!("{base}/v4/oauth2/{domain_id}");
    let now = chrono::Utc::now().timestamp();
    let access_lifetime = i64::from(oauth2_cfg.access_token_lifetime_minutes) * 60;
    let jti = uuid::Uuid::new_v4().to_string();
    let mut claims = openstack_keystone_core::oauth2_client::build_external_assertion_claims(
        client,
        &vsc,
        &issuer,
        jti,
        ruleset_version,
        now,
        now + access_lifetime,
        assertion_exp,
        audience,
    )
    .map_err(|error| {
        tracing::warn!(error = %error, "external assertion token claims could not be built");
        Oauth2TokenError::invalid_grant("subject_token does not permit token issuance")
    })?;
    let token_type = super::dpop::token_type(confirmation.as_ref());
    claims.cnf = confirmation;
    let access_token = super::common::sign_jwt(state, domain_id, &claims).await?;

    emit_oauth2_session_event(
        &state.audit_dispatcher,
        correlation_id,
        "authenticate",
        build_initiator_from_vsc(&vsc),
        &client.client_id,
        Outcome::Success,
        None,
    );

    let response = TokenResponse {
        issued_token_type: Some(ACCESS_TOKEN_TYPE),
        access_token,
        token_type,
        expires_in: claims.exp - now,
        scope,
        id_token: None,
        refresh_token: None,
    };
    Ok((StatusCode::OK, Json(response)).into_response())
}

fn extract_unverified_issuer(token: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?)
            .ok()?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty() && issuer.len() <= 2048)
        .map(str::to_string)
}

async fn load_identity_provider_jwks(
    idp: &IdentityProvider,
) -> Result<jsonwebtoken::jwk::JwkSet, Oauth2TokenError> {
    let client = oidc_utils::build_http_client().map_err(|error| {
        tracing::error!(error = %error, "external assertion HTTP client creation failed");
        Oauth2TokenError::internal("subject_token validation failed")
    })?;
    let jwks_uri = if let Some(jwks_url) = idp.jwks_url.as_deref() {
        jwks_url.to_string()
    } else if let Some(discovery_url) = idp.oidc_discovery_url.as_deref() {
        oidc_utils::discover(discovery_url, &client)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "external assertion discovery failed");
                Oauth2TokenError::internal("subject_token validation failed")
            })?
            .jwks_uri
    } else {
        tracing::error!(
            identity_provider_id = %idp.id,
            has_static_keys = idp.jwt_validation_pubkeys.as_ref().is_some_and(|keys| !keys.is_empty()),
            "identity provider has no usable JWKS configuration"
        );
        return Err(Oauth2TokenError::internal(
            "identity provider has no usable JWKS configuration",
        ));
    };
    oidc_utils::fetch_jwks(&jwks_uri, &client)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "external assertion JWKS fetch failed");
            Oauth2TokenError::internal("subject_token validation failed")
        })
}

#[async_trait::async_trait]
trait AssertionReplayProtection: Send + Sync {
    async fn check_and_record(
        &self,
        domain_id: &str,
        issuer: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<(), ReplayProtectionError>;
}

#[derive(Debug)]
enum ReplayProtectionError {
    Unavailable,
    #[cfg_attr(not(test), allow(dead_code))]
    Replayed,
}

struct ReplayProtectionUnavailable;

#[async_trait::async_trait]
impl AssertionReplayProtection for ReplayProtectionUnavailable {
    async fn check_and_record(
        &self,
        _domain_id: &str,
        _issuer: &str,
        _jti: &str,
        _expires_at: i64,
    ) -> Result<(), ReplayProtectionError> {
        Err(ReplayProtectionError::Unavailable)
    }
}

fn map_replay_protection_error(error: ReplayProtectionError) -> Oauth2TokenError {
    match error {
        ReplayProtectionError::Unavailable => Oauth2TokenError::server_error_unavailable(
            "external assertion replay protection is not available",
        ),
        ReplayProtectionError::Replayed => {
            Oauth2TokenError::invalid_grant("subject_token assertion has already been used")
        }
    }
}

fn map_mapping_error(error: AuthenticationError) -> Oauth2TokenError {
    tracing::warn!(error = %error, "external assertion mapping rejected");
    match error {
        AuthenticationError::Unauthorized
        | AuthenticationError::NoAuthorizationsFound
        | AuthenticationError::MultipleScopesForbidden
        | AuthenticationError::UserDisabled(_)
        | AuthenticationError::UserDomainDisabled
        | AuthenticationError::DomainDisabled(_)
        | AuthenticationError::ProjectDisabled(_) => {
            Oauth2TokenError::invalid_grant("subject_token claims could not be mapped")
        }
        AuthenticationError::Provider { .. }
        | AuthenticationError::StructBuilder { .. }
        | AuthenticationError::RoleConversionFailed => {
            Oauth2TokenError::internal("subject_token mapping failed")
        }
        _ => Oauth2TokenError::invalid_grant("subject_token claims could not be mapped"),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Mutex};

    use httpmock::prelude::*;
    use serde_json::json;

    use openstack_keystone_core_types::mapping::resolution::IdentitySource;
    use openstack_keystone_core_types::{
        federation::IdentityProvider, oauth2_client::OAuth2ClientResource,
    };

    use super::*;
    use crate::api::v4::oauth2::token::test_fixtures::{
        confidential_client, json_body, jwt_claims, matching_ruleset, ok_key_mock,
        successful_auth_result,
    };
    use crate::federation::MockFederationProvider;
    use crate::federation::api::oidc_utils::fixtures::{TEST_KID, make_jwt, rsa_jwk};
    use crate::mapping::MockMappingProvider;
    use crate::provider::Provider;
    use crate::resource::MockResourceProvider;

    const EXTERNAL_ISSUER: &str = "https://issuer.example";

    #[derive(Default)]
    struct TestReplayProtection(Mutex<HashSet<(String, String, String)>>);

    #[async_trait::async_trait]
    impl AssertionReplayProtection for TestReplayProtection {
        async fn check_and_record(
            &self,
            domain_id: &str,
            issuer: &str,
            jti: &str,
            _expires_at: i64,
        ) -> Result<(), ReplayProtectionError> {
            let Ok(mut seen) = self.0.lock() else {
                return Err(ReplayProtectionError::Unavailable);
            };
            if seen.insert((domain_id.to_string(), issuer.to_string(), jti.to_string())) {
                Ok(())
            } else {
                Err(ReplayProtectionError::Replayed)
            }
        }
    }

    async fn test_state(
        issuer: &str,
        idp: Option<IdentityProvider>,
        configure_mapping: bool,
    ) -> crate::keystone::ServiceState {
        let expected_issuer = issuer.to_string();
        let mut federation = MockFederationProvider::default();
        federation
            .expect_get_identity_provider_by_issuer()
            .returning(move |_, domain_id, requested_issuer| {
                assert_eq!(domain_id, "domain-1");
                assert_eq!(requested_issuer, expected_issuer);
                Ok(idp.clone())
            });

        let mut mapping = MockMappingProvider::default();
        if configure_mapping {
            let source = IdentitySource::TokenExchange {
                issuer: issuer.to_string(),
            };
            let ruleset_source = source.clone();
            let mut ruleset = matching_ruleset();
            ruleset.source = source.clone();
            mapping.expect_get_ruleset_by_source().returning(
                move |_, domain_id, requested_source| {
                    assert_eq!(domain_id, "domain-1");
                    assert_eq!(requested_source, &ruleset_source);
                    Ok(Some(ruleset.clone()))
                },
            );
            let expected_source = source.clone();
            let expected_issuer = issuer.to_string();
            mapping
                .expect_authenticate_by_mapping()
                .returning(move |_, request| {
                    assert_eq!(request.domain_id.as_deref(), Some("domain-1"));
                    assert_eq!(request.source, expected_source);
                    assert_eq!(request.unique_workload_id, "external-user");
                    assert!(request.claims["iss"].contains(&expected_issuer));
                    assert!(request.claims["sub"].contains(&"external-user".to_string()));
                    assert!(request.claims["aud"].contains(&assertion_audience()));
                    assert!(request.claims["jti"].contains(&"assertion-1".to_string()));
                    Ok(successful_auth_result())
                });
        }

        let mut resource = MockResourceProvider::default();
        resource.expect_get_domain_ref().returning(|_, _| {
            Ok(Some(openstack_keystone_core_types::resource::DomainRef {
                id: "domain-1".to_string(),
                name: "domain-1".to_string(),
                enabled: true,
            }))
        });

        let provider = Provider::mocked_builder()
            .mock_federation(federation)
            .mock_mapping(mapping)
            .mock_resource(resource)
            .mock_oauth2_key(ok_key_mock());
        openstack_keystone_core::api::tests::get_mocked_state(provider, true, None).await
    }

    fn test_idp(issuer: &str, jwks_url: &str) -> IdentityProvider {
        IdentityProvider {
            id: "idp-1".to_string(),
            enabled: true,
            bound_issuer: Some(issuer.to_string()),
            jwks_url: Some(jwks_url.to_string()),
            ..Default::default()
        }
    }

    async fn exchange(
        state: &crate::keystone::ServiceState,
        subject_token: String,
        replay_protection: &dyn AssertionReplayProtection,
    ) -> Result<Response, Oauth2TokenError> {
        let client: OAuth2ClientResource = confidential_client().await;
        handle_external_assertion_exchange_with_replay(
            state,
            "domain-1",
            &HeaderMap::new(),
            "test-correlation",
            &TokenForm::default(),
            &client,
            subject_token,
            None,
            "openstack:api".to_string(),
            &Oauth2Provider {
                access_token_lifetime_minutes: 1,
                ..Default::default()
            },
            replay_protection,
        )
        .await
    }

    async fn production_exchange(
        state: &crate::keystone::ServiceState,
        subject_token: String,
    ) -> Result<Response, Oauth2TokenError> {
        let client: OAuth2ClientResource = confidential_client().await;
        handle_external_assertion_exchange(
            state,
            "domain-1",
            &HeaderMap::new(),
            "test-correlation",
            &TokenForm::default(),
            &client,
            subject_token,
            None,
            "openstack:api".to_string(),
            &Oauth2Provider {
                access_token_lifetime_minutes: 1,
                ..Default::default()
            },
        )
        .await
    }

    async fn jwks_server() -> (MockServer, String) {
        let server = MockServer::start_async().await;
        let jwks = json!({"keys": [rsa_jwk(TEST_KID)]});
        server
            .mock_async(|when, then| {
                when.method(GET).path("/jwks");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(jwks);
            })
            .await;
        let url = format!("{}/jwks", server.base_url());
        (server, url)
    }

    fn assertion_token(issuer: &str, audience: &str, jti: &str, kid: &str) -> (String, i64) {
        let exp = chrono::Utc::now().timestamp() + 45;
        let claims = json!({
            "iss": issuer,
            "sub": "external-user",
            "aud": audience,
            "exp": exp,
            "jti": jti,
        });
        (make_jwt(&claims, Some(kid)), exp)
    }

    fn assertion_audience() -> String {
        "http://localhost/v4/oauth2/domain-1/token".to_string()
    }

    #[test]
    fn issuer_extraction_only_selects_a_candidate() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://issuer.example"}"#);
        assert_eq!(
            extract_unverified_issuer(&format!("header.{payload}.signature")),
            Some("https://issuer.example".to_string())
        );
        assert_eq!(extract_unverified_issuer("not.a.jwt.extra"), None);
        assert_eq!(extract_unverified_issuer("header.e30.signature"), None);
    }

    #[tokio::test]
    async fn production_handler_fails_closed_before_mapping_without_replay_cache() {
        let (_server, jwks_url) = jwks_server().await;
        let idp = test_idp(EXTERNAL_ISSUER, &jwks_url);
        let state = test_state(EXTERNAL_ISSUER, Some(idp), false).await;
        let (token, _) = assertion_token(
            EXTERNAL_ISSUER,
            &assertion_audience(),
            "assertion-1",
            TEST_KID,
        );

        let Err(error) = production_exchange(&state, token).await else {
            panic!("production exchange must fail closed without replay protection");
        };
        assert_eq!(error.error_code(), "server_error");
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn external_exchange_verifies_maps_mints_claims_and_rejects_replay() {
        let (_server, jwks_url) = jwks_server().await;
        let idp = test_idp(EXTERNAL_ISSUER, &jwks_url);
        let state = test_state(EXTERNAL_ISSUER, Some(idp), true).await;
        let (token, assertion_exp) = assertion_token(
            EXTERNAL_ISSUER,
            &assertion_audience(),
            "assertion-1",
            TEST_KID,
        );
        let replay_protection = TestReplayProtection::default();

        let Ok(response) = exchange(&state, token.clone(), &replay_protection).await else {
            panic!("valid external assertion exchange should succeed");
        };
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let Some(access_token) = body["access_token"].as_str() else {
            panic!("response contains an access token");
        };
        let claims = jwt_claims(access_token);
        assert_eq!(claims["iss"], "http://localhost/v4/oauth2/domain-1");
        assert_eq!(claims["sub"], "shadow-1");
        assert_eq!(claims["aud"], "openstack-apis");
        assert_eq!(claims["exp"].as_i64(), Some(assertion_exp));
        assert_eq!(claims["keystone_ruleset_version"], 7);
        assert_eq!(claims["amr"][0], "external_jwt");
        assert_eq!(claims["user_id"], "shadow-1");
        assert_eq!(claims["roles"][0], "member");

        let Err(error) = exchange(&state, token, &replay_protection).await else {
            panic!("replayed assertion should be rejected");
        };
        assert_eq!(error.error_code(), "invalid_grant");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn external_exchange_rejects_untrusted_issuer_before_mapping() {
        let untrusted_issuer = "https://untrusted.example";
        let state = test_state(untrusted_issuer, None, false).await;
        let (token, _) = assertion_token(
            untrusted_issuer,
            &assertion_audience(),
            "assertion-untrusted",
            TEST_KID,
        );

        let Err(error) = exchange(&state, token, &TestReplayProtection::default()).await else {
            panic!("untrusted issuer should be rejected");
        };
        assert_eq!(error.error_code(), "invalid_grant");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn external_exchange_rejects_bad_signatures_audiences_and_expired_tokens() {
        let (_server, jwks_url) = jwks_server().await;
        let idp = test_idp(EXTERNAL_ISSUER, &jwks_url);
        let state = test_state(EXTERNAL_ISSUER, Some(idp), false).await;

        let (wrong_audience, _) = assertion_token(
            EXTERNAL_ISSUER,
            "https://other.example/token",
            "wrong-audience",
            TEST_KID,
        );
        let expired_claims = json!({
            "iss": EXTERNAL_ISSUER,
            "sub": "external-user",
            "aud": assertion_audience(),
            "exp": chrono::Utc::now().timestamp() - 120,
            "jti": "expired",
        });
        let expired = make_jwt(&expired_claims, Some(TEST_KID));
        let mut bad_signature = assertion_token(
            EXTERNAL_ISSUER,
            &assertion_audience(),
            "bad-signature",
            TEST_KID,
        )
        .0;
        let Some(signature_start) = bad_signature.rfind('.').map(|dot| dot + 1) else {
            panic!("generated JWT has a signature segment");
        };
        let replacement = if bad_signature.as_bytes()[signature_start] == b'A' {
            "B"
        } else {
            "A"
        };
        bad_signature.replace_range(signature_start..signature_start + 1, replacement);
        for token in [bad_signature, wrong_audience, expired] {
            let Err(error) = exchange(&state, token, &TestReplayProtection::default()).await else {
                panic!("invalid assertion should be rejected");
            };
            assert_eq!(error.error_code(), "invalid_grant");
            assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn identity_provider_discovery_resolves_jwks() {
        let server = MockServer::start_async().await;
        let server_base_url = server.base_url();
        let jwks_uri = format!("{server_base_url}/keys");
        let discovery_document = json!({
            "issuer": server_base_url,
            "authorization_endpoint": format!("{server_base_url}/authorize"),
            "token_endpoint": format!("{server_base_url}/token"),
            "jwks_uri": jwks_uri,
        });
        let jwks = json!({"keys": [rsa_jwk(TEST_KID)]});
        server
            .mock_async(|when, then| {
                when.method(GET).path("/.well-known/openid-configuration");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(discovery_document);
            })
            .await;
        server
            .mock_async(|when, then| {
                when.method(GET).path("/keys");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(jwks);
            })
            .await;
        let idp = IdentityProvider {
            id: "idp-1".to_string(),
            oidc_discovery_url: Some(server_base_url),
            ..Default::default()
        };

        let Ok(jwks) = load_identity_provider_jwks(&idp).await else {
            panic!("valid discovery metadata should resolve JWKS");
        };
        assert_eq!(jwks.keys.len(), 1);
    }
}
