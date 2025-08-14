use crate::config::Config;
use crate::models::{LoginReq, LoginRes};
use reqwest::blocking::RequestBuilder;
use reqwest::header::HeaderMap;
use reqwest::Error;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cell::RefCell;
use std::time::{Duration, Instant};

pub struct Client {
    account_id: String,
    api_key: String,
    username: String,
    password: String,
    client: reqwest::blocking::Client,
    config: Config,
    // Use RefCell to allow interior mutability for token storage
    auth_state: RefCell<Option<AuthState>>,
}

#[derive(Debug)]
struct AuthState {
    access_token: String,
    refresh_token: String,
    expires_at: Instant,
    refresh_expires_at: Instant,
}

impl AuthState {
    fn from_login_response(login_res: &LoginRes) -> Self {
        let now = Instant::now();

        // Parse expires_in (in seconds) from the OAuth token
        let expires_in_seconds: u64 = login_res.oauth_token.expires_in.parse().unwrap_or(60); // Default to 60 seconds if parsing fails

        // Access token expires based on expires_in field
        let expires_at = now + Duration::from_secs(expires_in_seconds);

        // Refresh token typically expires 10 minutes after access token expiry
        // as mentioned in the IG docs
        let refresh_expires_at = expires_at + Duration::from_secs(10 * 60);

        Self {
            access_token: login_res.oauth_token.access_token.clone(),
            refresh_token: login_res.oauth_token.refresh_token.clone(),
            expires_at,
            refresh_expires_at,
        }
    }
}

fn get_url(config: &Config, endpoint: &String) -> String {
    format!("https://{}{}", config.base_url, endpoint)
}

impl Client {
    pub fn new(
        account_id: String,
        api_key: String,
        username: String,
        password: String,
        config: Config,
    ) -> Client {
        Client {
            account_id,
            api_key,
            username,
            password,
            config,
            client: reqwest::blocking::Client::new(),
            auth_state: RefCell::new(None),
        }
    }

    pub fn get_signed<T: DeserializeOwned, U: Serialize>(
        &self,
        endpoint: &String,
        version: u8,
        query: Option<U>,
    ) -> Result<T, Error> {
        let url = get_url(&self.config, endpoint);
        let mut req = self.set_headers(self.client.get(url), version)?;

        if let Some(query) = query {
            req = req.query(&query);
        }

        let res = req.send()?;
        Ok(res.json::<T>()?)
    }

    pub fn post_signed<T: DeserializeOwned, U: Serialize>(
        &self,
        endpoint: &String,
        version: u8,
        data: Option<U>,
    ) -> Result<T, Error> {
        let url = get_url(&self.config, endpoint);
        let mut req = self.set_headers(self.client.post(url), version)?;

        if let Some(data) = data {
            req = req.json(&data);
        }

        let res = req.send()?;
        Ok(res.json::<T>()?)
    }

    pub fn put_signed<T: DeserializeOwned, U: Serialize>(
        &self,
        endpoint: &String,
        version: u8,
        data: Option<U>,
    ) -> Result<T, Error> {
        let url = get_url(&self.config, endpoint);
        let mut req = self.set_headers(self.client.put(url), version)?;

        if let Some(data) = data {
            req = req.json(&data);
        }

        let res = req.send()?;
        Ok(res.json::<T>()?)
    }

    pub fn delete_signed<T: DeserializeOwned, U: Serialize>(
        &self,
        endpoint: &String,
        version: u8,
        data: Option<U>,
    ) -> Result<T, Error> {
        let url = get_url(&self.config, endpoint);
        let mut req = self.set_headers(self.client.post(url), version)?;

        let mut headers = HeaderMap::new();
        headers.insert("_method", "DELETE".to_string().parse().unwrap());
        req = req.headers(headers);

        if let Some(data) = data {
            req = req.json(&data);
        }

        let res = req.send()?;
        Ok(res.json::<T>()?)
    }

    /// Get a valid access token, reusing existing one if still valid,
    /// refreshing if possible, or logging in fresh if needed
    fn get_valid_access_token(&self) -> Result<String, Error> {
        let mut auth_state = self.auth_state.borrow_mut();
        let now = Instant::now();

        // Check if we have a valid access token
        if let Some(ref state) = *auth_state {
            if now < state.expires_at {
                // Token is still valid, reuse it
                return Ok(state.access_token.clone());
            }

            // Access token expired, try to refresh if refresh token is still valid
            if now < state.refresh_expires_at {
                match self.refresh_token(&state.refresh_token) {
                    Ok(login_res) => {
                        // Update the auth state with new tokens
                        let new_state = AuthState::from_login_response(&login_res);
                        let access_token = new_state.access_token.clone();
                        *auth_state = Some(new_state);
                        return Ok(access_token);
                    }
                    Err(_) => {
                        // Refresh failed, will fall through to fresh login
                    }
                }
            }
        }

        // No valid token or refresh failed, perform fresh login
        let login_res = self.fresh_login()?;
        let new_state = AuthState::from_login_response(&login_res);
        let access_token = new_state.access_token.clone();
        *auth_state = Some(new_state);
        Ok(access_token)
    }

    /// Perform a fresh login to get new tokens
    fn fresh_login(&self) -> Result<LoginRes, Error> {
        let login = LoginReq {
            identifier: self.username.clone(),
            password: self.password.clone(),
        };

        let mut headers = HeaderMap::new();
        headers.insert("X-IG-API-KEY", self.api_key.parse().unwrap());
        headers.insert("IG-ACCOUNT-ID", self.account_id.parse().unwrap());
        headers.insert("VERSION", "3".parse().unwrap());

        let url = get_url(&self.config, &"/session".into());
        let res = self
            .client
            .post(&url)
            .headers(headers)
            .json(&login)
            .send()?;
        res.json::<LoginRes>()
    }

    /// Refresh an access token using a refresh token
    fn refresh_token(&self, refresh_token: &str) -> Result<LoginRes, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("X-IG-API-KEY", self.api_key.parse().unwrap());
        headers.insert("IG-ACCOUNT-ID", self.account_id.parse().unwrap());
        headers.insert("VERSION", "1".parse().unwrap());

        let refresh_data = serde_json::json!({
            "refresh_token": refresh_token
        });

        let url = get_url(&self.config, &"/session/refresh-token".into());
        let res = self
            .client
            .post(&url)
            .headers(headers)
            .json(&refresh_data)
            .send()?;
        res.json::<LoginRes>()
    }

    fn set_headers(&self, req: RequestBuilder, version: u8) -> Result<RequestBuilder, Error> {
        let access_token = self.get_valid_access_token()?;
        let authorization = format!("Bearer {}", access_token);

        let mut headers = HeaderMap::new();
        headers.insert("IG-ACCOUNT-ID", self.account_id.parse().unwrap());
        headers.insert("X-IG-API-KEY", self.api_key.parse().unwrap());
        headers.insert("Authorization", authorization.parse().unwrap());
        headers.insert("VERSION", version.to_string().parse().unwrap());
        Ok(req.headers(headers))
    }
}
