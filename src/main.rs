mod error;
mod rpc_conf;

use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    Router,
    routing::{get, post}
};
use config::{Config, File};
use near_crypto::InMemorySigner;
#[cfg(test)]
use near_crypto::{KeyType, PublicKey, Signature};
use near_fetch::signer::KeyRotatingSigner;
#[cfg(test)]
use near_primitives::borsh::BorshSerialize;
use near_primitives::borsh::BorshDeserialize;
#[cfg(test)]
use near_primitives::delegate_action::{DelegateAction, NonDelegateAction};
use near_primitives::delegate_action::SignedDelegateAction;
#[cfg(test)]
use near_primitives::transaction::TransferAction;
use near_primitives::transaction::{Action, FunctionCallAction};
#[cfg(test)]
use near_primitives::types::{BlockHeight, Nonce};
use near_primitives::types::AccountId;
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::json;
use std::{fmt, path::Path};
use std::fmt::{Debug, Display, Formatter};
use std::net::SocketAddr;
use std::string::ToString;
#[cfg(test)]
use axum::body::{BoxBody, HttpBody};
#[cfg(test)]
use axum::response::Response;
#[cfg(test)]
use bytes::BytesMut;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};
use tracing::log::error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::{OpenApi, ToSchema};
use utoipa_rapidoc::RapiDoc;
use utoipa_swagger_ui::SwaggerUi;

use crate::error::RelayError;
use crate::rpc_conf::NetworkConfig;



// load config from toml and setup json rpc client
static LOCAL_CONF: Lazy<Config> = Lazy::new(|| {
    Config::builder()
        .add_source(File::with_name("config.toml"))
        .build()
        .unwrap()
});
static NETWORK_ENV: Lazy<String> = Lazy::new(|| { LOCAL_CONF.get("network").unwrap() });
static RPC_CLIENT: Lazy<near_fetch::Client> = Lazy::new(|| {
    let network_config = NetworkConfig {
        rpc_url: LOCAL_CONF.get("rpc_url").unwrap(),
        rpc_api_key: LOCAL_CONF.get("rpc_api_key").unwrap(),
        wallet_url: LOCAL_CONF.get("wallet_url").unwrap(),
        explorer_transaction_url: LOCAL_CONF.get("explorer_transaction_url").unwrap(),
    };
    network_config.rpc_client()
});
static IP_ADDRESS: Lazy<[u8; 4]> = Lazy::new(|| { LOCAL_CONF.get("ip_address").unwrap() });
static PORT: Lazy<u16> = Lazy::new(|| { LOCAL_CONF.get("port").unwrap() });
static RELAYER_ACCOUNT_ID: Lazy<String> = Lazy::new(|| {
    LOCAL_CONF.get("relayer_account_id").unwrap()
});
static SIGNER: Lazy<KeyRotatingSigner> = Lazy::new(|| {
    let paths = LOCAL_CONF.get::<Vec<String>>("keys_filenames")
        .expect("Failed to read 'keys_filenames' from config");
    KeyRotatingSigner::from_signers(paths.iter().map(|path| {
        InMemorySigner::from_file(Path::new(path))
            .unwrap_or_else(|err| panic!("failed to read signing keys from {path}: {err:?}"))
    }))
});
static USE_PAY_WITH_FT: Lazy<bool> = Lazy::new(|| {
   LOCAL_CONF.get("use_pay_with_ft").unwrap_or(false)
});
static BURN_ADDRESS: Lazy<String> = Lazy::new(||{
   LOCAL_CONF.get("burn_address").unwrap()
});

#[derive(Clone, Debug, Deserialize, ToSchema)]
struct AccountIdAllowanceOauthSDAJson {
    #[schema(example = "example.near")]
    account_id: String,
    #[schema(example = 900000000)]
    allowance: u64,
    #[schema(example = "https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2")]
    oauth_token: String,
    // NOTE: imported SignedDelegateAction itself doesn't have a corresponding schema in the OpenAPI document
    #[schema(example = "{\"delegate_action\": {\"actions\": [{\"Transfer\": {\"deposit\": \"1\" }}], \"max_block_height\": 922790412, \"nonce\": 103066617000686, \"public_key\": \"ed25519:98GtfFzez3opomVpwa7i4m2nptHtc8Ha405XHMWszQtL\", \"receiver_id\": \"relayer.example.testnet\", \"sender_id\": \"example.testnet\" }, \"signature\": \"ed25519:4uJu8KapH98h8cQm4btE0DKnbiFXSZNT7McDw4LHy7pdAt4Mz8DfuyQZadGgFExo77or9152iwcw2q12rnFWa6bg\" }")]
    signed_delegate_action: SignedDelegateAction,
}
impl Display for AccountIdAllowanceOauthSDAJson {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "account_id: {}, allowance in Gas: {}, oauth_token: {}, signed_delegate_action signature: {}",
            self.account_id, self.allowance, self.oauth_token, self.signed_delegate_action.signature
        )  // SignedDelegateAction doesn't implement display, so just displaying signature
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
struct AccountIdAllowanceOauthJson {
    #[schema(example = "example.near")]
    account_id: String,
    #[schema(example = 900000000)]
    allowance: u64,
    #[schema(example = "https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2")]
    oauth_token: String,
}
impl Display for AccountIdAllowanceOauthJson {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "account_id: {}, allowance in Gas: {}, oauth_token: {}",
            self.account_id, self.allowance, self.oauth_token
        )
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
struct AccountIdAllowanceJson {
    #[schema(example = "example.near")]
    account_id: String,
    #[schema(example = 900000000)]
    allowance: u64,
}
impl Display for AccountIdAllowanceJson {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "account_id: {}, allowance in Gas: {}",
            self.account_id, self.allowance
        )
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
struct AccountIdJson {
    #[schema(example = "example.near")]
    account_id: String,
}
impl Display for AccountIdJson {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "account_id: {}", self.account_id)
    }
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
struct AllowanceJson {  // TODO: LP use for return type of GET get_allowance
    #[schema(example = 900000000)]
    allowance_in_gas: u64,
}
impl Display for AllowanceJson {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "allowance in Gas: {}", self.allowance_in_gas)
    }
}


#[tokio::main]
async fn main() {
    // initialize tracing (aka logging)
    tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).init();

    //TODO: not secure, allow only for testnet, whitelist endpoint etc. for mainnet
    let cors_layer = tower_http::cors::CorsLayer::permissive();

    #[derive(OpenApi)]
    #[openapi(
        info(
            title = "relayer",
            description = "APIs for creating accounts, managing allowances, and relaying meta transactions. \
                    \n NOTE: the SignedDelegateAction is not supported by the openapi schema. \
                    \n Here's an example json of a SignedDelegateAction payload:\
                    \n ```{\"delegate_action\": {\"actions\": [{\"Transfer\": {\"deposit\": \"1\" }}], \"max_block_height\": 922790412, \"nonce\": 103066617000686, \"public_key\": \"ed25519:98GtfFzez3opomVpwa7i4m2nptHtc8Ha405XHMWszQtL\", \"receiver_id\": \"relayer.example.testnet\", \"sender_id\": \"example.testnet\" }, \"signature\": \"ed25519:4uJu8KapH98h8cQm4btE0DKnbiFXSZNT7McDw4LHy7pdAt4Mz8DfuyQZadGgFExo77or9152iwcw2q12rnFWa6bg\" }``` \
                    \n For more details on the SignedDelegateAction data structure, please see https://docs.rs/near-primitives/latest/near_primitives/delegate_action/struct.SignedDelegateAction.html or https://docs.near.org/develop/relayers/build-relayer#signing-a-delegated-transaction "
        ),
        paths(
            relay,
            send_meta_tx,
            create_account_atomic,
        ),
        components(
            schemas(
                RelayError,
                AllowanceJson,
                AccountIdJson,
                AccountIdAllowanceJson,
                AccountIdAllowanceOauthJson,
                AccountIdAllowanceOauthSDAJson,
            )
        ),
        tags((
            name = "relayer",
            description = "APIs for creating accounts, managing allowances, \
                                    and relaying meta transactions"
        )),
    )]
    struct ApiDoc;

    // build our application with a route
    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui")
            .url("/api-docs/openapi.json", ApiDoc::openapi()))
        // There is no need to create `RapiDoc::with_openapi` because the OpenApi is served
        // via SwaggerUi instead we only make rapidoc to point to the existing doc.
        .merge(RapiDoc::new("/api-docs/openapi.json").path("/rapidoc"))
        // Alternative to above
        // .merge(RapiDoc::with_openapi("/api-docs/openapi2.json", ApiDoc::openapi()).path("/rapidoc"))
        // `POST /relay` goes to `relay` handler function
        .route("/relay", post(relay))
        .route("/send_meta_tx", post(send_meta_tx))
        .route("/create_account_atomic", post(create_account_atomic))
        // See https://docs.rs/tower-http/0.1.1/tower_http/trace/index.html for more details.
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr: SocketAddr = SocketAddr::from((IP_ADDRESS.clone(), PORT.clone()));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}


// TODO: LP how to get multiple 500 status messages to show up
#[utoipa::path(
    post,
    path = "/create_account_atomic",
    request_body = AccountIdAllowanceOauthSDAJson,
    responses(
        (status = 201, description = "Added Oauth token https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2 for account_id example.near \
                            with allowance (in Gas) 90000000000000 to Relayer DB. \
                            Near onchain account creation response: {create_account_sda_result:?}", body = String),
        (status = 400, description = "Error: oauth_token https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2 has already been used to register an account. You can only register 1 account per oauth_token", body = String),
        (status = 403, description = "Invalid account_id: invalid_account_id.near", body = String),
        (status = 500, description = "Error getting oauth_token for account_id example.near, oauth_token https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2 in Relayer DB: err_msg", body = String),
        (status = 500, description = "Error creating account_id example.near with allowance 90000000000000 in Relayer DB:\nerr_msg", body = String),
        (status = 500, description = "Error allocating storage for account example.near: err_msg", body = String),
        (status = 500, description = "Error creating oauth token https://securetoken.google.com/pagoda-oboarding-dev:Op4h13AQozM4CikngfHiFVC2xhf2 in Relayer DB:\n{err:?}", body = String),
    ),
)]
async fn create_account_atomic(
    account_id_allowance_oauth_sda: Json<AccountIdAllowanceOauthSDAJson>
) -> impl IntoResponse {
    /*
    This function atomically creates an account, both in our systems (redis)
    and on chain created both an on chain account and adding that account to the storage pool

    Motivation for doing this is when calling /register_account_and_allowance and then /send_meta_tx and
    /register_account_and_allowance succeeds, but /send_meta_tx fails, then the account is now
    unable to use the relayer without manual intervention deleting the record from redis
     */

    // get individual vars from json object
    let account_id: &String = &account_id_allowance_oauth_sda.account_id;
    let allowance_in_gas: &u64 = &account_id_allowance_oauth_sda.allowance;
    let oauth_token: &String = &account_id_allowance_oauth_sda.oauth_token;
    let sda: SignedDelegateAction = account_id_allowance_oauth_sda.signed_delegate_action.clone();

    /*
        call process_signed_delegate_action fn
        if there's an error, then return error
        if it succeeds, then add oauth token to redis and allocate shared storage
        after updated redis and adding shared storage, finally return success msg
     */
    let create_account_sda_result = process_signed_delegate_action(sda).await;
    if create_account_sda_result.is_err() {
        let err: RelayError = create_account_sda_result.err().unwrap();
        return (err.status_code, err.message).into_response();
    }
    let Ok(account_id) = account_id.parse::<AccountId>() else {
        let err_msg = format!("Invalid account_id: {account_id}");
        warn!("{err_msg}");
        return (StatusCode::BAD_REQUEST, err_msg).into_response();
    };

    let ok_msg = format!(
        "Added Oauth token {oauth_token:?} for account_id {account_id:?} \
        with allowance (in Gas) {allowance_in_gas:?} to Relayer DB. \
        Near onchain account creation response: {create_account_sda_result:?}"
    );
    info!("{ok_msg}");
    (
        StatusCode::CREATED,
        ok_msg,
    ).into_response()
}


#[utoipa::path(
    post,
    path = "/relay",
    request_body = Vec<u8>,
    responses(
        (status = 201, description = "Relayed and sent transaction ...", body = String),
        (status = 400, description = "Error deserializing payload data object ...", body = String),
        (status = 500, description = "Error signing transaction: ...", body = String),
    ),
)]
async fn relay(
    data: Json<Vec<u8>>,
) -> impl IntoResponse {
    // deserialize SignedDelegateAction using borsh
    match SignedDelegateAction::try_from_slice(&data.0) {
        Ok(signed_delegate_action) => match process_signed_delegate_action(
            signed_delegate_action,
        ).await {
            Ok(response) => response.into_response(),
            Err(err) => (err.status_code, err.message).into_response(),
        },
        Err(e) => {
            let err_msg = format!(
                "{}: {:?}", "Error deserializing payload data object", e.to_string(),
            );
            warn!("{err_msg}");
            (StatusCode::BAD_REQUEST, err_msg).into_response()
        },
    }
}

#[utoipa::path(
    post,
    path = "/send_meta_tx",
    request_body = SignedDelegateAction,
    responses(
        (status = 201, description = "Relayed and sent transaction ...", body = String),
        (status = 400, description = "Error deserializing payload data object ...", body = String),
        (status = 500, description = "Error signing transaction: ...", body = String),
    ),
)]
async fn send_meta_tx(
    data: Json<SignedDelegateAction>,
) -> impl IntoResponse {
    let relayer_response = process_signed_delegate_action(
        // deserialize SignedDelegateAction using serde json
        data.0,
    ).await;
    match relayer_response {
        Ok(response) => response.into_response(),
        Err(err) => (err.status_code, err.message).into_response(),
    }
}


async fn process_signed_delegate_action(
    signed_delegate_action: SignedDelegateAction,
) -> Result<String, RelayError> {
    debug!("Deserialized SignedDelegateAction object: {:#?}", signed_delegate_action);

    // create Transaction from SignedDelegateAction
    let signer_account_id: AccountId = RELAYER_ACCOUNT_ID.as_str().parse().unwrap();
    // the receiver of the txn is the sender of the signed delegate action
    let receiver_id = signed_delegate_action.delegate_action.sender_id.clone();
    let da_receiver_id = signed_delegate_action.delegate_action.receiver_id.clone();


    // Check if the SignedDelegateAction includes a FunctionCallAction that transfers FTs to BURN_ADDRESS
    if USE_PAY_WITH_FT.clone() {
        let non_delegate_actions = signed_delegate_action.delegate_action.get_actions();
        let treasury_payments: Vec<Action> = non_delegate_actions
            .into_iter()
            .filter(|x| matches!(
                x,
                Action::FunctionCall(FunctionCallAction { args, .. }
                ) if String::from_utf8_lossy(args).contains(&BURN_ADDRESS.to_string()))
            )
            .collect();
        if treasury_payments.is_empty() {
            let err_msg = format!("No treasury payment found in this transaction", );
            warn!("{err_msg}");
            return Err(RelayError {
                status_code: StatusCode::BAD_REQUEST,
                message: err_msg,
            });
        }
    }


    let actions = vec![Action::Delegate(signed_delegate_action)];
    let execution = RPC_CLIENT.send_tx(&*SIGNER, &receiver_id, actions)
        .await
        .map_err(|err| {
            let err_msg = format!("Error signing transaction: {err:?}");
            error!("{err_msg}");
            RelayError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: err_msg,
            }
        })?;

    let status = &execution.status;
    let mut response_msg: String = "".to_string();
    match status {
        near_primitives::views::FinalExecutionStatus::Failure(_) => {
            response_msg = "Error sending transaction".to_string();
        }
        _ => {
            response_msg = "Relayed and sent transaction".to_string();
        }
    }
    let status_msg = json!({
        "message": response_msg,
        "status": &execution.status,
        "Transaction Outcome": &execution.transaction_outcome,
        "Receipts Outcome": &execution.receipts_outcome,
    });

    match status {
        near_primitives::views::FinalExecutionStatus::Failure(_) => {
            error!("Error message: \n{status_msg:?}");
            Err(RelayError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: status_msg.to_string(),
            })
        }
        _ => {
            info!("Success message: \n{status_msg:?}");
            Ok(status_msg.to_string())
        }
    }
    
}

/**
--------------------------- Testing below here ---------------------------
 */
#[cfg(test)]
fn create_signed_delegate_action(
    sender_id: String,
    receiver_id: String,
    actions: Vec<Action>,
    nonce: i32,
    max_block_height: i32,
) -> SignedDelegateAction {
    let max_block_height: i32 = max_block_height;
    let public_key: PublicKey = PublicKey::empty(KeyType::ED25519);
    let signature: Signature = Signature::empty(KeyType::ED25519);
    SignedDelegateAction {
        delegate_action: DelegateAction {
            sender_id: sender_id.parse().unwrap(),
            receiver_id: receiver_id.parse().unwrap(),
            actions: actions
                .iter()
                .map(|a| NonDelegateAction::try_from(a.clone()).unwrap())
                .collect(),
            nonce: nonce as Nonce,
            max_block_height: max_block_height as BlockHeight,
            public_key,
        },
        signature,
    }
}

#[cfg(test)]
async fn read_body_to_string(mut body: BoxBody) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // helper fn to convert the awful BoxBody dtype into a String so I can view the darn msg
    let mut bytes = BytesMut::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk?);
    }
    Ok(String::from_utf8(bytes.to_vec())?)
}

#[tokio::test]
// NOTE: uncomment ignore locally to run test bc redis doesn't work in github action build env
#[ignore]
async fn test_send_meta_tx() {   // tests assume testnet in config
    // Test Transfer Action
    let actions = vec![Action::Transfer(TransferAction { deposit: 1 })];
    let sender_id: String = String::from("relayer_test0.testnet");
    let receiver_id: String = String::from("relayer_test1.testnet");
    let nonce: i32 = 1;
    let max_block_height = 2000000000;

    // simulate calling the '/update_allowance' function with sender_id & allowance
    let allowance_in_gas: u64 = u64::MAX;

    // Call the `/send_meta_tx` function happy path
    let signed_delegate_action = create_signed_delegate_action(
        sender_id.clone(),
        receiver_id.clone(),
        actions.clone(),
        nonce,
        max_block_height,
    );
    let json_payload = Json(signed_delegate_action);
    println!("SignedDelegateAction Json Serialized (no borsh): {:?}", json_payload);
    let response: Response = send_meta_tx(json_payload).await.into_response();
    let response_status: StatusCode = response.status();
    let body: BoxBody = response.into_body();
    let body_str: String = read_body_to_string(body).await.unwrap();
    println!("Response body: {body_str:?}");
    assert_eq!(response_status, StatusCode::OK);
}

#[tokio::test]
async fn test_send_meta_tx_no_gas_allowance() {
    let actions = vec![Action::Transfer(TransferAction { deposit: 1 })];
    let sender_id: String = String::from("relayer_test0.testnet");
    let receiver_id: String = String::from("arrr_me_not_in_whitelist");
    let nonce: i32 = 54321;
    let max_block_height = 2000000123;

    // Call the `send_meta_tx` function with a sender that has no gas allowance
    // (and a receiver_id that isn't in whitelist)
    let sda2 = create_signed_delegate_action(
        sender_id.clone(),
        receiver_id.clone(),
        actions.clone(),
        nonce,
        max_block_height,
    );
    let non_whitelist_json_payload = Json(sda2);
    println!("SignedDelegateAction Json Serialized (no borsh) receiver_id not in whitelist: {:?}", non_whitelist_json_payload);
    let err_response = send_meta_tx(non_whitelist_json_payload).await.into_response();
    let err_response_status = err_response.status();
    let body: BoxBody = err_response.into_body();
    let body_str: String = read_body_to_string(body).await.unwrap();
    println!("Response body: {body_str:?}");
    assert!(err_response_status == StatusCode::BAD_REQUEST || err_response_status == StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
#[ignore]
async fn test_relay_with_load() {   // tests assume testnet in config
    // Test Transfer Action

    let actions = vec![
        Action::Transfer(TransferAction { deposit: 1 })
    ];
    let account_id0: String = "nomnomnom.testnet".to_string();
    let account_id1: String = "relayer_test0.testnet".to_string();
    let mut sender_id: String = String::new();
    let mut receiver_id: String = String::new();
    let mut nonce: i32 = 1;
    let max_block_height = 2000000000;

    let num_tests = 100;
    let mut response_statuses = vec![];
    let mut response_bodies = vec![];

    // fire off all post requests in rapid succession and save the response status codes
    for i in 0..num_tests {
        if i % 2 == 0 {
            sender_id.push_str(&*account_id0.clone());
            receiver_id.push_str(&*account_id1.clone());
        } else {
            sender_id.push_str(&*account_id1.clone());
            receiver_id.push_str(&*account_id0.clone());
        }
        // Call the `relay` function happy path
        let signed_delegate_action = create_signed_delegate_action(
            sender_id.clone(),
            receiver_id.clone(),
            actions.clone(),
            nonce.clone(),
            max_block_height.clone(),
        );
        let json_payload = signed_delegate_action.try_to_vec().unwrap();
        let response = relay(Json(Vec::from(json_payload))).await.into_response();
        response_statuses.push(response.status());
        let body: BoxBody = response.into_body();
        let body_str: String = read_body_to_string(body).await.unwrap();
        response_bodies.push(body_str);

        // increment nonce & reset sender, receiver strs
        nonce += 1;
        sender_id.clear();
        receiver_id.clear();
    }

    // all responses should be successful
    for i in 0..response_statuses.len() {
        let response_status = response_statuses[i].clone();
        println!("{}", response_status);
        println!("{}", response_bodies[i]);
        assert_eq!(response_status, StatusCode::OK);
    }
}
