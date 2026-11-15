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

    // Fail closed until the shared bounded assertion replay cache from #1640
    // is available on this branch. Do this before mapping, which can create or
    // update local identity records.
    require_assertion_replay_protection(
        domain_id,
        &unverified_issuer,
        assertion_jti,
        assertion_exp,
    )?;

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

fn require_assertion_replay_protection(
    _domain_id: &str,
    _issuer: &str,
    _jti: &str,
    _expires_at: i64,
) -> Result<(), Oauth2TokenError> {
    Err(Oauth2TokenError::server_error_unavailable(
        "external assertion replay protection is not available",
    ))
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
    use super::*;

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

    #[test]
    fn external_assertion_issuance_fails_closed_without_replay_cache() {
        let error = require_assertion_replay_protection("domain", "issuer", "jti", 100)
            .expect_err("cache is not wired");
        assert_eq!(error.error_code(), "server_error");
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
