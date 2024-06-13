use std::collections::HashMap;

use super::*;

#[tokio::test]
async fn test_new() {
    let tk = client::Turnkey::new().unwrap();
    let mut body = HashMap::new();
    body.insert(
        "organisationId".to_owned(),
        serde_json::to_value("XXX").unwrap(),
    );
    let req = client::RequestInput {
        uri: "/public/v1/query/list_wallets".to_owned(),
        method: "POST".to_owned(),
        headers: None,
        query: None,
        body: Some(body),
        substitution: None,
    };
    let resp: api::GetWalletsResponse = tk.request(req).await.unwrap();
}
