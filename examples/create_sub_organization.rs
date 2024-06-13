use std::{env, process};

use rust_sdk::client::{self, CreateSubOrganisation};
use rust_sdk::gen::external::activity::v1::CreateSubOrganizationRequest;
use rust_sdk::gen::immutable::activity::v1::{
    ApiKeyParams, CreateSubOrganizationIntentV4, RootUserParams,
};

#[tokio::main]
async fn main() {
    env_logger::init();
    dotenv::dotenv().ok();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: create_sub_organization NAME");
        process::exit(1);
    }
    let sub_organization_name = args[1].clone();

    let organization_id = env::var("TURNKEY_ORGANIZATION_ID").unwrap();
    let root_user_public_key = env::var("TURNKEY_API_PUBLIC_KEY").unwrap();

    let tk = client::Turnkey::new_from_env().unwrap();

    let timestamp_ms = tk.request_timestamp_ms();
    let req = CreateSubOrganizationRequest {
        organization_id,
        r#type: "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V4".to_owned(),
        timestamp_ms,
        parameters: Some(CreateSubOrganizationIntentV4 {
            sub_organization_name,
            root_users: vec![RootUserParams {
                user_name: "root".to_owned(),
                user_email: None,
                api_keys: vec![ApiKeyParams {
                    api_key_name: "root_public_key".to_owned(),
                    public_key: root_user_public_key,
                    expiration_seconds: None,
                }],
                authenticators: vec![],
            }],
            root_quorum_threshold: 1,
            wallet: None,
            disable_email_recovery: None,
            disable_email_auth: None,
        }),
    };
    let resp = tk.request::<CreateSubOrganisation>(req).await.unwrap();
    println!("{:#?}", resp);
}
