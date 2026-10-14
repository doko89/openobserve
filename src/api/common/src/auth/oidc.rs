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

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use base64::Engine;
use config::get_config;
use jsonwebtoken::{DecodingKey, Validation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build OIDC HTTP client")
});

struct CachedDiscovery {
    doc: DiscoveryDocument,
    fetched_at: Instant,
}

static DISCOVERY_CACHE: LazyLock<tokio::sync::RwLock<Option<CachedDiscovery>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(None));

struct CachedJwks {
    keys: Jwks,
    fetched_at: Instant,
}

static JWKS_CACHE: LazyLock<tokio::sync::RwLock<Option<CachedJwks>>> =
    LazyLock::new(|| tokio::sync::RwLock::new(None));

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub iat: Option<u64>,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
}

pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

pub fn is_enabled() -> bool {
    let cfg = get_config();
    cfg.auth.oidc_enabled
        && !cfg.auth.oidc_issuer_url.is_empty()
        && !cfg.auth.oidc_client_id.is_empty()
}

pub async fn discover() -> Result<DiscoveryDocument, anyhow::Error> {
    {
        let cache = DISCOVERY_CACHE.read().await;
        if let Some(cached) = cache.as_ref()
            && cached.fetched_at.elapsed() < DISCOVERY_TTL
        {
            return Ok(cached.doc.clone());
        }
    }

    let cfg = get_config();
    let issuer = cfg.auth.oidc_issuer_url.trim_end_matches('/');
    let url = format!("{issuer}{DISCOVERY_PATH}");

    let doc: DiscoveryDocument = HTTP_CLIENT
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("OIDC discovery returned error: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery JSON parse failed: {e}"))?;

    let mut cache = DISCOVERY_CACHE.write().await;
    *cache = Some(CachedDiscovery {
        doc: doc.clone(),
        fetched_at: Instant::now(),
    });
    Ok(doc)
}

pub fn generate_pkce() -> PkcePair {
    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut verifier_bytes);
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    PkcePair {
        code_verifier,
        code_challenge,
    }
}

pub fn generate_state() -> String {
    let mut state_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut state_bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes)
}

pub fn build_authorization_url(
    discovery: &DiscoveryDocument,
    pkce: &PkcePair,
    state: &str,
) -> String {
    let cfg = get_config();
    let scopes = &cfg.auth.oidc_scopes;
    let mut url = Url::parse(&discovery.authorization_endpoint)
        .expect("OIDC authorization_endpoint must be a valid URL");
    {
        let mut params = url.query_pairs_mut();
        params.append_pair("response_type", "code");
        params.append_pair("client_id", &cfg.auth.oidc_client_id);
        params.append_pair("redirect_uri", &cfg.auth.oidc_redirect_url);
        params.append_pair("scope", scopes);
        params.append_pair("state", state);
        params.append_pair("code_challenge", &pkce.code_challenge);
        params.append_pair("code_challenge_method", "S256");
    }
    url.to_string()
}

pub async fn exchange_code(
    code: &str,
    code_verifier: &str,
) -> Result<TokenResponse, anyhow::Error> {
    let cfg = get_config();
    let discovery = discover().await?;

    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.auth.oidc_redirect_url.as_str()),
        ("code_verifier", code_verifier),
        ("client_id", cfg.auth.oidc_client_id.as_str()),
    ];
    if !cfg.auth.oidc_client_secret.is_empty() {
        params.push(("client_secret", cfg.auth.oidc_client_secret.as_str()));
    }

    HTTP_CLIENT
        .post(&discovery.token_endpoint)
        .form(&params)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC token exchange request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("OIDC token exchange returned error: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC token exchange JSON parse failed: {e}"))
}

pub async fn validate_id_token(id_token: &str) -> Result<OidcClaims, anyhow::Error> {
    let cfg = get_config();
    let jwks = get_jwks().await?;

    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| anyhow::anyhow!("OIDC ID token header decode failed: {e}"))?;

    let kid = header
        .kid
        .ok_or_else(|| anyhow::anyhow!("OIDC ID token missing kid header"))?;

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid.as_deref() == Some(&kid))
        .ok_or_else(|| anyhow::anyhow!("OIDC ID token kid '{kid}' not found in JWKS"))?;

    let decoding_key = jwk_to_decoding_key(jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&cfg.auth.oidc_issuer_url]);
    validation.validate_aud = true;
    validation.set_audience(&[&cfg.auth.oidc_client_id]);

    let token_data = jsonwebtoken::decode::<OidcClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| anyhow::anyhow!("OIDC ID token validation failed: {e}"))?;

    Ok(token_data.claims)
}

async fn get_jwks() -> Result<Jwks, anyhow::Error> {
    {
        let cache = JWKS_CACHE.read().await;
        if let Some(cached) = cache.as_ref()
            && cached.fetched_at.elapsed() < DISCOVERY_TTL
        {
            return Ok(cached.keys.clone());
        }
    }

    let discovery = discover().await?;
    let keys: Jwks = HTTP_CLIENT
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC JWKS request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("OIDC JWKS returned error: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC JWKS JSON parse failed: {e}"))?;

    let mut cache = JWKS_CACHE.write().await;
    *cache = Some(CachedJwks {
        keys: keys.clone(),
        fetched_at: Instant::now(),
    });
    Ok(keys)
}

fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, anyhow::Error> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("RSA JWK missing n"))?;
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("RSA JWK missing e"))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| anyhow::anyhow!("Failed to build RSA decoding key: {e}"))
        }
        "EC" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("EC JWK missing x"))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("EC JWK missing y"))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| anyhow::anyhow!("Failed to build EC decoding key: {e}"))
        }
        kty => Err(anyhow::anyhow!("Unsupported JWK key type: {kty}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_roundtrip() {
        let pair = generate_pkce();
        assert!(!pair.code_verifier.is_empty());
        assert!(!pair.code_challenge.is_empty());
        assert_ne!(pair.code_verifier, pair.code_challenge);

        let digest = Sha256::digest(pair.code_verifier.as_bytes());
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(pair.code_challenge, expected);
    }

    #[test]
    fn test_state_is_random() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2);
        assert!(!s1.is_empty());
    }

    #[test]
    fn test_jwk_to_decoding_key_rsa() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: Some("test".to_string()),
            n: Some("modulus".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        };
        // Invalid modulus will fail, but at least it should take the RSA path
        assert!(jwk_to_decoding_key(&jwk).is_err());
    }

    #[test]
    fn test_jwk_to_decoding_key_unsupported() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(jwk_to_decoding_key(&jwk).is_err());
    }
}
