# Pagoda Relayer

## What is a Relayer?
At a high level, the Relayer is a http server that relays transactions to the NEAR network via RPC on behalf of new users who haven't yet acquired NEAR as part of the onboarding process. The entity running the relayer covers the gas costs for the end users who are signing the transactions.

## How does a Relayer work?
This functionality depends on [NEP-366: Meta Transactions](https://github.com/near/NEPs/pull/366).

Technically, the end user (client) creates a `SignedDelegateAction` that contains the data necessary to construct a `Transaction`, signs the `SignedDelegateAction` using their key, which is then serialized and sent  to the relayer (server) as payload of a POST request. 
When the request is received, the relayer uses its own key to sign a `Transaction` using the fields in the `SignedDelegateAction` as input to create a `SignedTransaction`. 
The `SignedTransaction` is then sent to the network via RPC call and the result is then sent back to the client.

## Why use a Relayer?
1. Your users are new to NEAR and don't have any gas to cover transactions 
2. Your users have an account on NEAR, but only have a Fungible Token Balance. They can now use the FT to pay for gas
3. As an enterprise or a large startup you want to seamlessly onboard your existing users onto NEAR without needing them to worry about gas costs and seed phrases
4. As an enterprise or large startup you have a userbase that can generate large spikes of user activity that would congest the network. In this case, the relayer acts as a queue for low urgency transactions  
5. In exchange for covering the gas fee costs, relayer operators can limit where users spend their assets while allowing users to have custody and ownership of their assets 
6. Capital Efficiency: Without relayer if your business has 1M users they would have to be allocated 0.25 NEAR to cover their gas costs totalling 250k NEAR. However, only ~10% of the users would actually use the full allowance and a large amount of the 250k NEAR is just sitting there unused. So using the relayer, you can allocate 50k NEAR as a global pool of capital for your users, which can refilled on an as needed basis.

## Features 
NOTE: These features can be mixed and matched "à la carte". Use of one feature does not preclude the use of any other feature unless specified. See the `/examples` directory for example configs corresponding to different use cases.
1. Cover the gas costs of end users while allowing them to maintain custody of their funds and approve transactions (`/relay`, `/send_meta_tx`)
2. Only pay for users interacting with certain contracts by whitelisting contracts addresses (`whitelisted_contracts` in `config.toml`) 
3. Specify gas cost allowances for all accounts (`/update_all_allowances`) or on a per-user account basis (`/create_account_atomic`, `/register_account`, `/update_allowance`) and keep track of allowances (`/get_allowance`)
4. Specify the accounts for which the relayer will cover gas fees (`whitelisted_delegate_action_receiver_ids` in `config.toml`)
5. Only allow users to register if they have a unique Oauth Token (`/create_account_atomic`, `/register_account`)
6. Relayer Key Rotation: `keys_filenames` in `config.toml`
7. Integrate with [Fastauth SDK](https://docs.near.org/tools/fastauth-sdk). See `/examples/configs/fastauth.toml`

### Features - COMING SOON
1. Allow users to pay for gas fees using Fungible Tokens they hold. This can be implemented by either:
   1. Swapping the FT for NEAR using a DEX like [Ref finance](https://app.ref.finance/) OR
   2. Sending the FT to a burn address that is verified by the relayer and the relayer covers the equivalent amount of gas in NEAR
2. Cover storage deposit costs by deploying a storage contract
3. Configure via to config use relayer without storage contract
4. automated relayer funds "top up" service
5. Put transactions in a queue to minimize network congestion - expected early-mid 2024
6. Multichain relayers - expected early-mid 2024

## API Spec <a id="api_spc"></a>
For more details on the following endpoint and to try them out, please [setup your local dev env](#basic_setup).
After you have started the server with `cargo run`,
open http://0.0.0.0:3030/swagger-ui/#/ in your browser to view the swagger docs and test out the endpoints with the example payloads.
Alternatively, you can open http://0.0.0.0:3030/rapidoc#overview for the rapidocs.
Both swagger and rapidoc are based on the openapi standard and generated using the [utoipa crate](https://crates.io/crates/utoipa).
These are helpful starter api docs and payloads, but not all example payloads will work on the endpoints in swagger-ui or rapidoc.

#### Known issues
1.  the SignedDelegateAction is not supported by the openapi schema. Replace
```json
"signed_delegate_action": "string"
``` 
with
```json
"signed_delegate_action": {
   "delegate_action": {
      "actions": [{
            "Transfer": {
                "deposit": "1"
            }
      }],
      "max_block_height": 122790412,
      "nonce": 103066617000686,
      "public_key": "ed25519:89GtfFzez3opomVpwa7i4m3nptHtc7Ha514XHMWszQtL",
      "receiver_id": "relayer.pagodaplatform.near",
      "sender_id": "relayer.pagodaplatform.near"
   },
   "signature": "ed25519:5uJu7KapH89h9cQm5btE1DKnbiFXSZNT7McDw5LHy8pdAt5Mz9DfuyQZadGgFExo88or9152iwcw2q12rnFWa6bg"
}
```
2. The `/relay` endpoint is [borsh](https://github.com/near/borsh) serialized representation of SignedDelegateAction (as opposed to json) and thus does not work with swagger or rapidoc. Please use a borsh serialized SignedDelegateAction that will look like:
```json
{
    "borsh_signed_delegate_action": [64, 0, 0, 0, 49, 48, 97, 102, 100, 99, 98, 101, 99, 99, 55, 100, 54, 55, 57, 57, 102, 102, 52, 48, 48, 49, 98, 56, 56, 100, 53, 56, 97, 57, 56, 50, 51, 55, 98, 98, 49, 100, 55, 100, 54, 100, 48, 99, 98, 99, 54, 102, 57, 100, 99, 102, 100, 57, 49, 51, 56, 97, 57, 50, 57, 53, 55, 56, 11, 0, 0, 0, 116, 111, 107, 101, 110, 46, 115, 119, 101, 97, 116, 2, 0, 0, 0, 2, 11, 0, 0, 0, 102, 116, 95, 116, 114, 97, 110, 115, 102, 101, 114, 139, 0, 0, 0, 123, 34, 114, 101, 99, 101, 105, 118, 101, 114, 95, 105, 100, 34, 58, 34, 101, 100, 100, 51, 97, 49, 55, 97, 99, 50, 51, 55, 102, 102, 98, 51, 50, 54, 54, 98, 48, 98, 101, 55, 48, 98, 100, 101, 97, 49, 48, 52, 53, 51, 50, 97, 101, 48, 98, 50, 101, 100, 102, 49, 48, 100, 57, 99, 50, 97, 53, 97, 48, 49, 53, 101, 52, 56, 99, 97, 52, 54, 52, 57, 34, 44, 34, 97, 109, 111, 117, 110, 116, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 44, 34, 109, 101, 109, 111, 34, 58, 34, 115, 119, 58, 116, 58, 57, 107, 118, 74, 69, 86, 119, 71, 107, 101, 34, 125, 0, 224, 6, 161, 187, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 11, 0, 0, 0, 102, 116, 95, 116, 114, 97, 110, 115, 102, 101, 114, 88, 0, 0, 0, 123, 34, 114, 101, 99, 101, 105, 118, 101, 114, 95, 105, 100, 34, 58, 34, 102, 101, 101, 115, 46, 115, 119, 101],
    "signature": "ed25519:3oBH35ETxwj2MJJmiQtB4WLps7CNBvhZ33y2zuamPjgbWVLBgUr47sLGVBmuoiA5nXtra9CJMEiHQNWZB8saGnFW"
}
```
3. The `/get_allowance` endpoint doesn't work in swagger, but works fine in Postman ¯\_(ツ)_/¯

For more extensive testing, especially when you've deployed the relayer to multiple environments, it is recommended that you use Postman or some other api testing service.
- POST `/relay`
- POST `/send_meta_tx`
- GET `/get_allowance`
- POST `/update_allowance`
- POST `/update_all_allowances`
- POST `/create_account_atomic`
- POST `/register_account`

## Basic Setup - Local Dev <a id="basic_setup"></a>
1. [Install Rust for NEAR Development](https://docs.near.org/sdk/rust/get-started)
2. If you don't have a NEAR account, [create one](https://docs.near.org/concepts/basics/accounts/creating-accounts)
3. With the account from step 2, create a json file in this directory in the format `{"account_id":"example.testnet","public_key":"ed25519:98GtfFzez3opomVpwa7i4m3nptHtc7Ha514XHMWszLtQ","private_key":"ed25519:YWuyKVQHE3rJQYRC3pRGV56o1qEtA1PnMYPDEtroc5kX4A4mWrJwF7XkzGe7JWNMABbtY4XFDBJEzgLyfPkwpzC"}` using a [Full Access Key](https://docs.near.org/concepts/basics/accounts/access-keys#key-types) from an account that has enough NEAR to cover the gas costs of transactions your server will be relaying. Usually, this will be a copy of the json file found in the `.near-credentials` directory. 
4. Update values in `config.toml`
5. Open up the `port` from `config.toml` in your machine's network settings
6. Run the server using `cargo run`. To run with logs (tracing) enabled run `RUST_LOG=tower_http=debug cargo run`

## Redis Setup - OPTIONAL 
NOTE: this is only needed if you intend to use whitelisting, allowances, and oauth functionality

1. [Install redis](https://redis.io/docs/getting-started/installation/). Steps 2 & 3 assume redis installed on machine instead of docker setup. If you're connecting to a redis instance running in gcp, follow the above steps to connect to a vm that will forward requests from your local relayer server to redis running in gcp: https://cloud.google.com/memorystore/docs/redis/connect-redis-instance#connecting_from_a_local_machine_with_port_forwarding
2. Run `redis-server --bind 127.0.0.1 --port 6379` - make sure the port matches the `redis_url` in the `config.toml`.
3. Run `redis-cli -h 127.0.0.1 -p 6379`

## Multiple Key Generation - OPTIONAL, but recommended for high throughput to prevent nonce race conditions
1. [Install NEAR CLI](https://docs.near.org/tools/near-cli#installation)
2. Make sure you're using the appropriate network: `echo $NEAR_ENV`. To change it, `export NEAR_ENV=testnet` 
3. Make sure your keys you want to use for the relayer have a `'FullAccess'` access_key by running `near keys your_relayer_account.testnet`. This is required to create more keys. You need to have access to at least 1 `'FullAccess'` access_key 
4. Generate a new implicit key: `near generate-key`
   1. This will output something like `Key pair with ed25519:GdsF992LXiwNiAGUtxL7VbcPBAckbYBZubF6fTYrVY5Q public key for an account "e05185d0de0d6e4897555a386fdd3f48508ad1cdeaebcbd1cac81c72116cc5ab"`
5. Add the newly generated key to the relayer account: `near add-key your_relayer_account.testnet ed25519:GdsF992LXiwNiAGUtxL7VbcPBAckbYBZubF6fTYrVY5Q`
   1. This will output something like: `Adding full access key = ed25519:GdsF992LXiwNiAGUtxL7VbcPBAckbYBZubF6fTYrVY5Q to your_relayer_account.testnet. Transaction Id Bur9nJxos4f5cbibYXugZQQmZ4Uo2jsHYiVUwPT7AZMG To see the transaction in the transaction explorer, please open this url in your browser https://explorer.testnet.near.org/transactions/Bur9nJxos4f5cbibYXugZQQmZ4Uo2jsHYiVUwPT7AZMG`
6. Repeat steps 4 & 5 until you have the desired number of keys. Anywhere between 5-20 full access keys added to the relayer account works for most cases. 
7. To double check your keys were successfully added to the account run `near keys your_relayer_account.testnet` again and you should see the newly added full access keys
8. Copy all the newly generated keyfiles (usually `.json` files located in` ~/.near-credentials` directory) into the `pagoda-relayer-rs` directory
9. Change all the `"account_id"`s of the keyfiles in the relayer directory from the implicit account_id (i.e. `e05185d0de0d6e4897555a386fdd3f48508ad1cdeaebcbd1cac81c72116cc5ab`) to the relayer account_id `your_relayer_account.testnet`
10. Add the key filenames (i.e. `"e05185d0de0d6e4897555a386fdd3f48508ad1cdeaebcbd1cac81c72116cc5ab.json"`) to the `keys_filenames` list in `config.toml`

## Testing
1. Run unit tests with `cargo test`

## Docker Deployment
1. Update `config.toml` as per your requirements.
2. Add any account key json files you need to use to the `account_keys` directory.
3. Update the `key_filenames` and `num_keys` parameter in the `config.toml` based on the keys you store in the `account_keys` directory.
4. Run command `docker compose up`
   this will create a `pagoda-relayer-rs` and `redis` container
   
    Run command `docker compose down` to stop the containers
5. Test the endpoints. See [API Spec](#api_spec)

## Cloud Deployment
The Relayer is best deployed in a serverless environment, such as AWS Lambda or GCP Cloud Run, to optimally manage automatic scalability and optimize cost. 

Alternatively, the relayer can be deployed on a VM instance if the expected traffic to the relayer (and thus the CPU, RAM requirements) is well known ahead of time.

For security, it is recommended that the Full Access Key credentials are stored in a Secret Manager Service. NOTE: there should not be an large amount of funds stored on the relayer account associated with the signing key. It is better to periodically "top up" the relayer account. "Top up" Service coming soon...
