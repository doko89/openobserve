// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use axum::{
    extract::Query,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::Engine;
use config::{
    get_config,
    meta::user::{DBUser, UserOrg, UserRole},
    utils::rand::generate_random_string,
};
use db::user;
use openobserve_api_common::auth::oidc;
use openobserve_core::auth::get_hash;
use serde::{Deserialize, Serialize};

const OIDC_STATE_COOKIE: &str = "oidc_login_state";
const OIDC_STATE_MAX_AGE_SECS: i64 = 600;
const AUTH_TOKENS_COOKIE: &str = "auth_tokens";

#[derive(Serialize, Deserialize)]
struct OidcLoginState {
    state: String,
    code_verifier: String,
}

fn state_cookie(value: &str, max_age: i64) -> Cookie<'static> {
    let cfg = get_config();
    let mut cookie = Cookie::new(OIDC_STATE_COOKIE, value.to_string());
    cookie.set_max_age(time::Duration::seconds(max_age));
    cookie.set_http_only(true);
    cookie.set_secure(cfg.auth.cookie_secure_only);
    cookie.set_path("/");
    if cfg.auth.cookie_same_site_lax {
        cookie.set_same_site(SameSite::Lax);
    } else {
        cookie.set_same_site(SameSite::None);
    }
    cookie
}

pub async fn oidc_login() -> Response {
    if !oidc::is_enabled() {
        return (
            StatusCode::FORBIDDEN,
            "OIDC is not enabled on this instance",
        )
            .into_response();
    }

    let discovery = match oidc::discover().await {
        Ok(d) => d,
        Err(e) => {
            log::error!("OIDC discovery failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "OIDC discovery failed").into_response();
        }
    };

    let pkce = oidc::generate_pkce();
    let state = oidc::generate_state();

    let login_state = OidcLoginState {
        state: state.clone(),
        code_verifier: pkce.code_verifier.clone(),
    };
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&login_state).unwrap_or_default());

    let auth_url = oidc::build_authorization_url(&discovery, &pkce, &state);

    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, &auth_url)
        .body(axum::body::Body::empty())
        .unwrap();

    if let Ok(v) =
        header::HeaderValue::from_str(&state_cookie(&encoded, OIDC_STATE_MAX_AGE_SECS).to_string())
    {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }

    resp
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn oidc_callback(jar: CookieJar, Query(query): Query<OidcCallbackQuery>) -> Response {
    if let Some(err) = &query.error {
        log::warn!("OIDC callback received error from IdP: {err}");
        return redirect_to_login(format!("SSO error: {err}"));
    }

    let code = match &query.code {
        Some(c) => c.clone(),
        None => return redirect_to_login("Missing authorization code".to_string()),
    };

    let returned_state = match &query.state {
        Some(s) => s.clone(),
        None => return redirect_to_login("Missing state parameter".to_string()),
    };

    let cookie = match jar.get(OIDC_STATE_COOKIE) {
        Some(c) => c,
        None => return redirect_to_login("Missing login state cookie".to_string()),
    };

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie.value())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<OidcLoginState>(&bytes).ok());

    let login_state = match decoded {
        Some(s) => s,
        None => return redirect_to_login("Invalid login state cookie".to_string()),
    };

    if login_state.state != returned_state {
        return redirect_to_login("State mismatch — possible CSRF".to_string());
    }

    let tokens = match oidc::exchange_code(&code, &login_state.code_verifier).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("OIDC token exchange failed: {e}");
            return redirect_to_login("Failed to exchange authorization code".to_string());
        }
    };

    let id_token = match &tokens.id_token {
        Some(t) => t.clone(),
        None => return redirect_to_login("No ID token in token response".to_string()),
    };

    let claims = match oidc::validate_id_token(&id_token).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("OIDC ID token validation failed: {e}");
            return redirect_to_login("Failed to validate ID token".to_string());
        }
    };

    let email = match claims.email.as_deref().filter(|e| !e.is_empty()) {
        Some(e) => e.to_lowercase(),
        None => match claims
            .preferred_username
            .as_deref()
            .filter(|e| e.contains('@'))
        {
            Some(e) => e.to_lowercase(),
            None => return redirect_to_login("No email claim in ID token".to_string()),
        },
    };

    let password = match ensure_oidc_user(&email, &claims).await {
        Ok(p) => p,
        Err(e) => {
            log::error!("OIDC user provisioning failed for {email}: {e}");
            return redirect_to_login("Failed to provision user".to_string());
        }
    };

    set_auth_cookie_and_redirect(&email, &password)
}

async fn ensure_oidc_user(email: &str, claims: &oidc::OidcClaims) -> Result<String, anyhow::Error> {
    if let Ok(existing) = user::get_db_user(email).await {
        return Ok(existing.password);
    }

    let cfg = get_config();
    let org_name = &cfg.auth.oidc_default_org;
    let role = match cfg.auth.oidc_default_role.as_str() {
        "viewer" => UserRole::Viewer,
        "editor" => UserRole::Editor,
        "user" => UserRole::User,
        _ => UserRole::Admin,
    };

    let password = generate_random_string(32);
    let salt = generate_random_string(8);
    let hashed_password = get_hash(&password, &salt);

    let first_name = claims
        .given_name
        .clone()
        .or_else(|| claims.name.clone())
        .unwrap_or_default();
    let last_name = claims.family_name.clone().unwrap_or_default();

    let db_user = DBUser {
        email: email.to_string(),
        first_name,
        last_name,
        password: hashed_password,
        salt,
        organizations: vec![UserOrg {
            name: org_name.clone(),
            org_name: org_name.clone(),
            token: generate_random_string(16),
            rum_token: None,
            role,
        }],
        is_external: false,
        password_ext: None,
    };

    user::add(&db_user).await?;
    log::info!("Auto-provisioned OIDC user: {email}");

    Ok(password)
}

fn set_auth_cookie_and_redirect(email: &str, password: &str) -> Response {
    let cfg = get_config();

    let access_token = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{email}:{password}"))
    );
    let tokens = serde_json::json!({
        "access_token": access_token,
        "refresh_token": "",
    });
    let encoded_tokens = base64::engine::general_purpose::STANDARD.encode(tokens.to_string());

    let mut auth_cookie = Cookie::new(AUTH_TOKENS_COOKIE, encoded_tokens);
    auth_cookie.set_max_age(time::Duration::seconds(cfg.auth.cookie_max_age));
    auth_cookie.set_http_only(true);
    auth_cookie.set_secure(cfg.auth.cookie_secure_only);
    auth_cookie.set_path("/");
    if cfg.auth.cookie_same_site_lax {
        auth_cookie.set_same_site(SameSite::Lax);
    } else {
        auth_cookie.set_same_site(SameSite::None);
    }

    let clear_state = state_cookie("", 0);

    let mut resp = Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/web/")
        .body(axum::body::Body::empty())
        .unwrap();

    if let Ok(v) = header::HeaderValue::from_str(&auth_cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    if let Ok(v) = header::HeaderValue::from_str(&clear_state.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }

    resp
}

fn redirect_to_login(message: String) -> Response {
    let encoded: String = urlencoding::encode(&message).to_string();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, format!("/web/login?error={encoded}"))
        .body(axum::body::Body::empty())
        .unwrap()
}
