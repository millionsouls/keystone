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
//! # `client_credentials` mapping-engine ingress (ADR 0026 §5, Phase 3)
//!
//! Mirrors `crate::api::api_key_auth::hydrate_ephemeral_context` exactly --
//! same `MappingRuleSet` match -> `authenticate_by_mapping` -> hydrated
//! [`ValidatedSecurityContext`] pipeline -- generalized to accept any of the
//! three scoped [`Authorization`] variants (API Key ingress is domain-only;
//! `client_credentials` is not restricted that way by the ADR).
use std::collections::HashMap;

use tracing::warn;

use openstack_keystone_core_types::auth::{AuthenticationError, ScopeInfo, SecurityContext};
use openstack_keystone_core_types::mapping::IdentitySource;
use openstack_keystone_core_types::mapping::auth::MappingAuthRequest;
use openstack_keystone_core_types::mapping::authorization::Authorization;
use openstack_keystone_core_types::mapping::virtual_user::MatchResult;
use openstack_keystone_core_types::oauth2_client::{
    Audience, DelegationContext, OAuth2ClientResource, OpenStackAccessTokenClaims,
    OpenStackContext, OpenStackScope,
};
use openstack_keystone_core_types::resource::ResourceProviderError;

use crate::auth::{ExecutionContext, IntoAuthContext, ValidatedSecurityContext};
use crate::keystone::ServiceState;
use crate::mapping::engine;
use crate::oauth2_client::Oauth2ClientProviderError;

/// Run the `client_credentials` client through the mapping engine and
/// return a fully hydrated [`ValidatedSecurityContext`], alongside the
/// matched ruleset's `ruleset_version` (for the minted token's
/// `keystone_ruleset_version` claim, ADR 0026 §4).
///
/// # Errors
/// [`AuthenticationError::Unauthorized`] for any failure along the pipeline
/// (no ruleset bound to this client's `provider_id`, disabled ruleset,
/// evaluation failure) -- deliberately not more specific, mirroring
/// `hydrate_ephemeral_context`'s posture of not leaking pipeline internals
/// to an unauthenticated caller. [`AuthenticationError::NoAuthorizationsFound`]
/// / [`AuthenticationError::MultipleScopesForbidden`] surface the same two
/// named invariants API Key ingress enforces.
pub async fn hydrate_client_credentials_context(
    state: &ServiceState,
    client: &OAuth2ClientResource,
) -> Result<(ValidatedSecurityContext, u128), AuthenticationError> {
    let source = IdentitySource::OAuth2Client {
        provider_id: client.provider_id.clone(),
    };
    let exec = ExecutionContext::internal(state);

    let ruleset = state
        .provider
        .get_mapping_provider()
        .get_ruleset_by_source(&exec, &client.domain_id, &source)
        .await
        .map_err(|e| {
            warn!(error = %e, "oauth2 client_credentials mapping ruleset lookup failed");
            AuthenticationError::Unauthorized
        })?
        .ok_or(AuthenticationError::Unauthorized)?;

    if !ruleset.enabled {
        return Err(AuthenticationError::Unauthorized);
    }

    let mut claims = HashMap::new();
    claims.insert(
        "oauth2_client.client_id".to_string(),
        vec![client.client_id.clone()],
    );
    claims.insert(
        "oauth2_client.provider_id".to_string(),
        vec![client.provider_id.clone()],
    );

    // Pre-evaluate to enforce the same invariants API Key ingress does
    // (no-authorizations / single-scope) before hydrating any context.
    // `authenticate_by_mapping` below independently re-evaluates the same
    // (ruleset, claims) pair -- evaluation is pure, so this is
    // deterministic.
    let match_result: Option<MatchResult> =
        engine::evaluate_ruleset(&ruleset, &claims, ruleset.domain_id.as_deref(), None).map_err(
            |e| {
                warn!(error = %e, "oauth2 client_credentials mapping evaluation failed");
                AuthenticationError::Unauthorized
            },
        )?;

    let authorization = match &match_result {
        None => return Err(AuthenticationError::NoAuthorizationsFound),
        Some(mr) if mr.authorizations.is_empty() => {
            return Err(AuthenticationError::NoAuthorizationsFound);
        }
        Some(mr) if mr.authorizations.len() > 1 => {
            return Err(AuthenticationError::MultipleScopesForbidden);
        }
        Some(mr) => &mr.authorizations[0],
    };

    let scope = scope_info_from_authorization(state, &exec, authorization).await?;
    scope.validate()?;

    let mapping_req = MappingAuthRequest {
        domain_id: Some(client.domain_id.clone()),
        source,
        unique_workload_id: client.client_id.clone(),
        claims,
        rule_name: None,
    };

    let auth_result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&exec, &mapping_req)
        .await
        .map_err(|e| {
            warn!(error = %e, "oauth2 client_credentials mapping authentication failed");
            AuthenticationError::Unauthorized
        })?;

    let ctx = SecurityContext::try_from(auth_result)?;
    let vsc = ValidatedSecurityContext::new_for_scope(ctx, scope, state).await?;
    Ok((vsc, ruleset.ruleset_version))
}

/// Run an external assertion's verified claims through the domain's token
/// exchange mapping ruleset and return a fully hydrated security context.
pub async fn hydrate_external_assertion_context(
    state: &ServiceState,
    domain_id: &str,
    issuer: &str,
    subject: &str,
    claims: HashMap<String, Vec<String>>,
) -> Result<(ValidatedSecurityContext, u128), AuthenticationError> {
    let source = IdentitySource::TokenExchange {
        issuer: issuer.to_string(),
    };
    let exec = ExecutionContext::internal(state);
    let ruleset = state
        .provider
        .get_mapping_provider()
        .get_ruleset_by_source(&exec, domain_id, &source)
        .await
        .map_err(|e| AuthenticationError::Provider {
            source: Box::new(e),
            context: Some("external assertion mapping ruleset lookup".to_string()),
        })?
        .ok_or(AuthenticationError::Unauthorized)?;

    if !ruleset.enabled {
        return Err(AuthenticationError::Unauthorized);
    }

    let match_result =
        engine::evaluate_ruleset(&ruleset, &claims, ruleset.domain_id.as_deref(), None).map_err(
            |e| AuthenticationError::Provider {
                source: Box::new(e),
                context: Some("external assertion mapping evaluation".to_string()),
            },
        )?;
    let authorization = match &match_result {
        None => return Err(AuthenticationError::NoAuthorizationsFound),
        Some(mr) if mr.authorizations.is_empty() => {
            return Err(AuthenticationError::NoAuthorizationsFound);
        }
        Some(mr) if mr.authorizations.len() > 1 => {
            return Err(AuthenticationError::MultipleScopesForbidden);
        }
        Some(mr) => &mr.authorizations[0],
    };

    let scope = scope_info_from_authorization(state, &exec, authorization).await?;
    scope.validate()?;

    let mapping_req = MappingAuthRequest {
        domain_id: Some(domain_id.to_string()),
        source,
        unique_workload_id: subject.to_string(),
        claims,
        rule_name: None,
    };
    let auth_result = state
        .provider
        .get_mapping_provider()
        .authenticate_by_mapping(&exec, &mapping_req)
        .await
        .map_err(|e| AuthenticationError::Provider {
            source: Box::new(e),
            context: Some("external assertion mapping authentication".to_string()),
        })?;

    let ctx = SecurityContext::try_from(auth_result)?;
    let vsc = ValidatedSecurityContext::new_for_scope(ctx, scope, state).await?;
    Ok((vsc, ruleset.ruleset_version))
}

/// Resolve the mapping-matched [`Authorization`] into a [`ScopeInfo`] backed
/// by the resource provider's live `Project`/`Domain` records, not by
/// ruleset-declared placeholders.
///
/// A ruleset is operator-authored configuration, but the `project_id`/
/// `domain_id` it names can still go stale (the resource deleted or
/// disabled after the ruleset was written, without the ruleset itself being
/// updated). Fetching the real record here -- rather than fabricating one
/// with `enabled: true` hardcoded -- is what makes the subsequent
/// `ScopeInfo::validate()` call during context hydration
/// meaningful: without it, `validate()` would only ever be checking its own
/// placeholder's `true` against itself.
///
/// # Errors
/// [`AuthenticationError::Provider`] if the named project/domain no longer
/// exists -- deliberately not a more specific "not found" surfaced to the
/// caller, mirroring this module's existing posture of not leaking pipeline
/// internals to an unauthenticated client.
async fn scope_info_from_authorization(
    state: &ServiceState,
    exec: &ExecutionContext<'_>,
    authorization: &Authorization,
) -> Result<ScopeInfo, AuthenticationError> {
    let resource_provider = state.provider.get_resource_provider();
    match authorization {
        Authorization::Project { project_id, .. } => {
            let project = resource_provider
                .get_project_ref(exec, project_id)
                .await
                .auth_context("fetching oauth2 mapping scope project")?
                .ok_or_else(|| ResourceProviderError::ProjectNotFound(project_id.clone()))
                .auth_context("fetching oauth2 mapping scope project")?;
            let project_domain = resource_provider
                .get_domain_ref(exec, &project.domain_id)
                .await
                .auth_context("fetching oauth2 mapping scope project domain")?
                .ok_or_else(|| ResourceProviderError::DomainNotFound(project.domain_id.clone()))
                .auth_context("fetching oauth2 mapping scope project domain")?;
            Ok(ScopeInfo::Project {
                project,
                project_domain,
            })
        }
        Authorization::Domain { domain_id, .. } => {
            let domain = resource_provider
                .get_domain_ref(exec, domain_id)
                .await
                .auth_context("fetching oauth2 mapping scope domain")?
                .ok_or_else(|| ResourceProviderError::DomainNotFound(domain_id.clone()))
                .auth_context("fetching oauth2 mapping scope domain")?;
            Ok(ScopeInfo::Domain(domain))
        }
        Authorization::System { system_id, .. } => Ok(ScopeInfo::System(system_id.clone())),
    }
}

/// Build the [`OpenStackAccessTokenClaims`] for a `client_credentials`
/// token, from the hydrated [`ValidatedSecurityContext`] returned by
/// [`hydrate_client_credentials_context`].
///
/// # Errors
/// [`Oauth2ClientProviderError::Validation`] if the hydrated context did not
/// resolve to a workload principal with a scoped authorization -- this
/// should never happen given `hydrate_client_credentials_context`'s own
/// invariants, but is checked rather than assumed since this function
/// serializes directly into a signed token.
#[allow(clippy::too_many_arguments)]
pub fn build_access_token_claims(
    client: &OAuth2ClientResource,
    vsc: &ValidatedSecurityContext,
    issuer: &str,
    jti: String,
    ruleset_version: u128,
    iat: i64,
    exp: i64,
) -> Result<OpenStackAccessTokenClaims, Oauth2ClientProviderError> {
    use openstack_keystone_core_types::auth::IdentityInfo;

    let principal = vsc.inner().principal();
    let IdentityInfo::Principal(pinfo) = &principal.identity else {
        return Err(Oauth2ClientProviderError::Validation(
            "client_credentials hydrated a non-workload principal".to_string(),
        ));
    };
    let user_id = pinfo.id.clone();
    let user_name = pinfo
        .resolved_user_name
        .clone()
        .unwrap_or_else(|| client.client_id.clone());
    let user_domain_id = pinfo.domain.as_ref().map(|d| d.id.clone());

    let authz = vsc.inner().authorization().ok_or_else(|| {
        Oauth2ClientProviderError::Validation(
            "client_credentials hydrated context has no authorization scope".to_string(),
        )
    })?;
    let role_refs = authz.effective_roles().unwrap_or(&[]).to_vec();
    let role_names: Vec<String> = role_refs.iter().filter_map(|r| r.name.clone()).collect();

    let scope = match &authz.scope {
        openstack_keystone_core_types::auth::ScopeInfo::Project {
            project,
            project_domain,
        } => OpenStackScope::Project {
            project_id: project.id.clone(),
            project_domain_id: project_domain.id.clone(),
            roles: role_refs,
        },
        openstack_keystone_core_types::auth::ScopeInfo::Domain(domain) => OpenStackScope::Domain {
            domain_id: domain.id.clone(),
            roles: role_refs,
        },
        openstack_keystone_core_types::auth::ScopeInfo::System(system_id) => {
            OpenStackScope::System {
                system_id: system_id.clone(),
                roles: role_refs,
            }
        }
        _ => OpenStackScope::Unscoped,
    };

    Ok(OpenStackAccessTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.clone(),
        aud: Audience::control_plane(),
        client_id: client.client_id.clone(),
        exp,
        iat,
        nbf: iat,
        jti,
        keystone_ruleset_version: ruleset_version,
        amr: vec!["client_credentials".to_string()],
        token_use: "access".to_string(),
        delegation_context: DelegationContext::Plain,
        act: None,
        openstack_context: OpenStackContext {
            user_id,
            user_name,
            user_domain_id,
            scope,
            roles: role_names,
        },
        cnf: None,
    })
}

/// Build claims for a token minted from an external assertion.
///
/// The returned token never outlives the validated assertion, even when the
/// configured access-token lifetime is longer.
#[allow(clippy::too_many_arguments)]
pub fn build_external_assertion_claims(
    client: &OAuth2ClientResource,
    vsc: &ValidatedSecurityContext,
    issuer: &str,
    jti: String,
    ruleset_version: u128,
    iat: i64,
    configured_exp: i64,
    assertion_exp: i64,
    audience: Audience,
) -> Result<OpenStackAccessTokenClaims, Oauth2ClientProviderError> {
    use openstack_keystone_core_types::auth::IdentityInfo;

    let identity = &vsc.inner().principal().identity;
    let (user_id, user_name, user_domain_id, amr) = match identity {
        IdentityInfo::User(user) => {
            let user_name = user
                .user
                .as_ref()
                .map(|record| record.name.clone())
                .unwrap_or_else(|| user.user_id.clone());
            (
                user.user_id.clone(),
                user_name,
                user.user_domain.as_ref().map(|domain| domain.id.clone()),
                vec!["external_jwt".to_string()],
            )
        }
        IdentityInfo::Principal(principal) => (
            principal.id.clone(),
            principal
                .resolved_user_name
                .clone()
                .unwrap_or_else(|| principal.id.clone()),
            principal.domain.as_ref().map(|domain| domain.id.clone()),
            vec!["external_jwt".to_string()],
        ),
    };

    let authz = vsc.inner().authorization().ok_or_else(|| {
        Oauth2ClientProviderError::Validation(
            "external assertion mapping has no authorization scope".to_string(),
        )
    })?;
    let scope_domain_id = match &authz.scope {
        ScopeInfo::Project { project_domain, .. } => project_domain.id.as_str(),
        ScopeInfo::Domain(domain) => domain.id.as_str(),
        ScopeInfo::System(_) => &client.domain_id,
        _ => {
            return Err(Oauth2ClientProviderError::Validation(
                "external assertion mapping has an unsupported scope".to_string(),
            ));
        }
    };
    if scope_domain_id != client.domain_id {
        return Err(Oauth2ClientProviderError::Validation(
            "external assertion mapping scope belongs to another domain".to_string(),
        ));
    }

    let exp = cap_external_assertion_expiry(configured_exp, assertion_exp, iat)?;

    let role_refs = authz.effective_roles().unwrap_or(&[]).to_vec();
    let role_names = role_refs
        .iter()
        .filter_map(|role| role.name.clone())
        .collect();
    let scope = match &authz.scope {
        ScopeInfo::Project {
            project,
            project_domain,
        } => OpenStackScope::Project {
            project_id: project.id.clone(),
            project_domain_id: project_domain.id.clone(),
            roles: role_refs,
        },
        ScopeInfo::Domain(domain) => OpenStackScope::Domain {
            domain_id: domain.id.clone(),
            roles: role_refs,
        },
        ScopeInfo::System(system_id) => OpenStackScope::System {
            system_id: system_id.clone(),
            roles: role_refs,
        },
        _ => OpenStackScope::Unscoped,
    };

    Ok(OpenStackAccessTokenClaims {
        iss: issuer.to_string(),
        sub: user_id.clone(),
        aud: audience,
        client_id: client.client_id.clone(),
        exp,
        iat,
        nbf: iat,
        jti,
        keystone_ruleset_version: ruleset_version,
        amr,
        token_use: "access".to_string(),
        delegation_context: DelegationContext::Plain,
        act: None,
        openstack_context: OpenStackContext {
            user_id,
            user_name,
            user_domain_id,
            scope,
            roles: role_names,
        },
        cnf: None,
    })
}

fn cap_external_assertion_expiry(
    configured_exp: i64,
    assertion_exp: i64,
    iat: i64,
) -> Result<i64, Oauth2ClientProviderError> {
    let exp = configured_exp.min(assertion_exp);
    if exp <= iat {
        return Err(Oauth2ClientProviderError::Validation(
            "external assertion expires before the access token can be issued".to_string(),
        ));
    }
    Ok(exp)
}

#[cfg(test)]
mod tests {
    use super::cap_external_assertion_expiry;

    #[test]
    fn external_token_expiry_never_exceeds_assertion_expiry() {
        assert!(cap_external_assertion_expiry(500, 300, 100).is_ok_and(|exp| exp == 300));
        assert!(cap_external_assertion_expiry(250, 300, 100).is_ok_and(|exp| exp == 250));
        assert!(cap_external_assertion_expiry(300, 100, 100).is_err());
    }
}
