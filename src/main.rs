use serde_json::Value;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use reqwest::header::CONTENT_LENGTH;
use std::collections::HashMap;
use std::net::TcpListener;
use std::io::prelude::Read;

const AUTH_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";

#[derive(Debug, Deserialize, Serialize)]
struct LinkedinSecrets {
    client_id: String,
    client_secret: String,
    redirect_uri: String
}

#[derive(Debug, Deserialize, Serialize)]
struct LinkedinToken {
    client_id: String,
    client_secret: String,
    access_token: String,
    expiry: i64,
    scope: String,
    refresh_token: Option<String>,
    refresh_token_expiry: Option<i64>,
}

impl LinkedinSecrets {
    fn from_file(path: &str) -> Result<LinkedinSecrets, std::io::Error> {
        let content = std::fs::read_to_string(&path)?;
        let output: LinkedinSecrets = serde_json::from_str(&content)
            .expect("Could not parse file.");
        Ok(output)
    }

    async fn auth(&self, scope: Option<String>, port: u32) -> Result<LinkedinToken, reqwest::Error> {
        let scope_ = match scope {
            Some(scope) => scope,
            None => "r_basicprofile".to_string()
        };
        let params = HashMap::from([
            ("response_type", "code"),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("scope", scope_.as_str())
        ]);
        let auth_url = reqwest::Url::parse_with_params(AUTH_URL, params)
            .expect("Could not parse url.");

        println!("Please visit this URL to authorize this application: {}", auth_url);

        let listener: TcpListener = 
            TcpListener::bind(format!("localhost:{}", port))
            .expect("Failed to bind to port.");
        
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0;2048];
        stream.read(&mut buf).unwrap();

        let buf_str: String = String::from_utf8_lossy(&buf[..]).to_string();
        let buf_vec: Vec<&str> = buf_str.split(" ").collect::<Vec<&str>>();

        let args: String = buf_vec[1].to_string();
        let callback_url = reqwest::Url::parse(
            (format!("http://localhost:{}", port) + &args).as_str()
        ).expect("Failed to parse callback URL");
        let query: HashMap<_,_> = callback_url.query_pairs().into_owned().collect();
        let code = query.get("code").unwrap().to_string();

        let params = HashMap::from([
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret)
        ]);
        
        let url = reqwest::Url::parse_with_params(TOKEN_URL, params)
            .expect("Failed to parse url.");

        let ts = chrono::Utc::now().timestamp_micros();

        let response = Client::new()
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(CONTENT_LENGTH, 0)
            .send()
            .await?;

        let content: Value = response.json()
            .await
            .expect("Failed to parse response.");

        let expiry = content["expires_in"].as_i64().unwrap() * 1000000 + ts;

        let refresh_token_expiry = match content.get("refresh_token") {
            Some(value) => Some(value.as_i64().unwrap() * 1000000 + ts),
            None => None
        };

        let refresh_token = match content.get("refresh_token") {
            Some(token) => Some(token.as_str().unwrap().to_string()),
            None => None
        };


        let output: LinkedinToken = LinkedinToken {
            client_id: self.client_id.to_string(),
            client_secret: self.client_secret.to_string(),
            access_token: content["access_token"].as_str().unwrap().to_string(),
            expiry: expiry,
            scope: content["scope"].as_str().unwrap().to_string(),
            refresh_token: refresh_token,
            refresh_token_expiry: refresh_token_expiry
        };

        Ok(output)
    }
}


impl LinkedinToken {
    fn from_file(path: &str) -> Result<LinkedinToken, std::io::Error> {
        let content = std::fs::read_to_string(&path)?;
        let output: LinkedinToken = serde_json::from_str(&content)
            .expect("Could not parse file.");
        Ok(output)
    }

    fn expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_micros();
        self.expiry < now
    }

    async fn refresh(&mut self) {
        let body: Value = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        });

        let ts = chrono::Utc::now().timestamp_micros();
        let response = Client::new()
            .post(TOKEN_URL)
            .json(&body)
            .send()
            .await
            .expect("Failed to refresh token.");

        let content: Value = response.json()
            .await
            .expect("Failed to parse response.");

        let expiry = content["expires_in"].as_i64().unwrap() + ts;
        self.access_token = content["access_token"].as_str().unwrap().to_string();
        self.expiry = expiry;
    }
}


const HELP_MSG: &str = "
Usage: linkedin-oauth <SERVICE> <JSON_PATH> [SCOPE] [PORT]

SERVICE: `auth`, or `refresh`
JSON_PATH: The path to the JSON file containing the credentials.
SCOPE: Only required for `auth`
PORT: Only required for `auth`
";

#[tokio::main]
async fn main() {
    // linkedin-oauth 
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 5 || args.len() == 1 {panic!("{}", HELP_MSG);}

    match args[1].as_str() {
        "auth" => {
            if args.len() != 5 {panic!("{}", HELP_MSG);}
            let secret = LinkedinSecrets::from_file(args[2].as_str())
                .expect("Cannot read/parse file.");
            let token = secret.auth(
                Some(args[3].to_string()), args[4].parse::<u32>().unwrap()
            ).await.unwrap();
            let output = serde_json::to_string_pretty(&token)
                .expect("Cannot serialize token.");
            println!("{}", output);
        },
        "refresh" => {
            if args.len() != 3 {panic!("{}", HELP_MSG);}
            let mut secret = LinkedinToken::from_file(args[2].as_str())
                .expect("Cannot read/parse file.");
            secret.refresh().await;
            std::fs::write(&args[1], serde_json::to_string_pretty(&secret).unwrap()).unwrap();
        }
        _ => {panic!("Only `auth` or `refresh` is allowed.");}
    }
}
