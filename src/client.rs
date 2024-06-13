use crate::errors::{StampError, TurnkeyError};
use crate::gen::services::coordinator::public::v1 as api;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::FieldBytes;
use reqwest::header::HeaderValue;
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::env;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiStamp {
    public_key: String,
    signature: String,
    scheme: String,
}

#[derive(Debug)]
struct StampInput<'a> {
    sealed_body: &'a str,
    public_key_hex: String,
    private_key_hex: String,
}

#[derive(Debug)]
struct SealedRequestInput {
    pub body: Value,
    pub public_key_hex: Option<String>,
    pub private_key_hex: Option<String>,
}

#[derive(Debug)]
struct SealedRequestOutput {
    pub sealed_body: String,
    pub x_stamp: String,
}

pub struct TurnkeyApiKey {
    pub private_key_hex: Option<String>,
    pub public_key_hex: Option<String>,
}

pub struct Turnkey {
    stamper: TurnkeyApiKey,
    base_url: String,
    client: Client,
}

pub type TurnkeyResult<T> = std::result::Result<T, TurnkeyError>;

impl Turnkey {
    pub fn new(base_url: String, stamper: TurnkeyApiKey) -> Self {
        Self {
            base_url,
            stamper,
            client: Client::new(),
        }
    }

    pub fn new_from_env() -> TurnkeyResult<Self> {
        Ok(Self {
            base_url: env::var("TURNKEY_BASE_URL")
                .map_err(|e| TurnkeyError::OtherError(e.to_string()))?,
            stamper: TurnkeyApiKey {
                private_key_hex: env::var("TURNKEY_API_PRIVATE_KEY")
                    .map_err(|e| TurnkeyError::OtherError(e.to_string()))
                    .ok(),
                public_key_hex: env::var("TURNKEY_API_PUBLIC_KEY")
                    .map_err(|e| TurnkeyError::OtherError(e.to_string()))
                    .ok(),
            },
            client: Client::new(),
        })
    }

    pub async fn request<RPC>(&self, request_input: RPC::Request) -> TurnkeyResult<RPC::Response>
    where
        RPC: TurnkeyRpc,
        RPC::Request: Serialize,
        RPC::Response: DeserializeOwned,
    {
        let body = serde_json::to_value(request_input).expect("serilization to succeed");
        let resp = self.raw_request(RPC::uri(), body).await?;
        Ok(resp)
    }

    fn stamp(&self, stamp_input: StampInput) -> TurnkeyResult<String> {
        let private_key_bytes = hex::decode(stamp_input.private_key_hex)
            .map_err(|e| TurnkeyError::StampError(StampError::InvalidPrivateKeyString(e)))?;

        let signing_key: SigningKey =
            SigningKey::from_bytes(FieldBytes::from_slice(&private_key_bytes))
                .map_err(|_| TurnkeyError::StampError(StampError::InvalidPrivateKeyBytes))?;

        let sig: Signature = signing_key.sign(stamp_input.sealed_body.as_bytes());
        let stamp = ApiStamp {
            public_key: stamp_input.public_key_hex.clone(),
            signature: hex::encode(sig.to_der()),
            scheme: "SIGNATURE_SCHEME_TK_API_P256".to_string(),
        };

        let json_stamp = serde_json::to_string(&stamp).unwrap();

        Ok(BASE64_URL_SAFE_NO_PAD.encode(json_stamp.as_bytes()))
    }

    async fn raw_request<O>(&self, uri: String, body: Value) -> TurnkeyResult<O>
    where
        O: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, uri);

        let sealed_request_input = SealedRequestInput {
            body,
            public_key_hex: None,
            private_key_hex: None,
        };
        let sealed_request_output = self
            .seal_and_stamp_request_body(sealed_request_input)
            .await?;

        let response = self
            .client
            .post(&url)
            .headers({
                let mut headers = reqwest::header::HeaderMap::new();
                if let Ok(x_stamp_header) =
                    HeaderValue::try_from(sealed_request_output.x_stamp.clone())
                {
                    headers.insert("X-Stamp", x_stamp_header);
                }
                headers
            })
            .body(sealed_request_output.sealed_body)
            .send()
            .await
            .map_err(TurnkeyError::HttpError)?;

        match response.status() {
            reqwest::StatusCode::OK => match response.json::<O>().await {
                Ok(parsed) => Ok(parsed),
                Err(e) => Err(TurnkeyError::OtherError(e.to_string())),
            },
            other => Err(TurnkeyError::OtherError(format!(
                "Received status code: {}",
                other
            ))),
        }
    }

    async fn seal_and_stamp_request_body(
        &self,
        input: SealedRequestInput,
    ) -> TurnkeyResult<SealedRequestOutput> {
        // TODO: Change the "or_else" into "unwrap_or" -> what's fallback val?
        let public_key_hex = input
            .public_key_hex
            .or_else(|| self.stamper.public_key_hex.clone())
            .ok_or_else(|| TurnkeyError::OtherError("No public key given or found".to_string()))?;

        let private_key_hex = input
            .private_key_hex
            .or_else(|| self.stamper.private_key_hex.clone())
            .ok_or_else(|| TurnkeyError::OtherError("No public key given or found".to_string()))?;

        let sealed_body = serde_json::to_string(&input.body)
            .map_err(|e| TurnkeyError::OtherError(e.to_string()))?;

        let stamp_input = StampInput {
            sealed_body: &sealed_body,
            public_key_hex,
            private_key_hex,
        };

        // Encoded serialized stamp
        let x_stamp = self.stamp(stamp_input)?;
        Ok(SealedRequestOutput {
            sealed_body,
            x_stamp,
        })
    }
}

pub trait TurnkeyRpc {
    fn uri() -> String;
    type Request;
    type Response;
}

pub struct GetWallets {}

impl TurnkeyRpc for GetWallets {
    fn uri() -> String {
        "/public/v1/query/list_wallets".to_owned()
    }

    type Request = api::GetWalletsRequest;
    type Response = api::GetWalletsResponse;
}
