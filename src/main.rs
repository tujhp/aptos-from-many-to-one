extern crate core;

use core::panicking::panic;
use anyhow::{Context, Result};
use aptos_sdk;
use aptos_sdk::bcs;
use aptos_sdk::coin_client::CoinClient;
use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::crypto::{ValidCryptoMaterialStringExt};
use aptos_sdk::move_types::identifier::Identifier;
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::rest_client::{Client, PendingTransaction};
use aptos_sdk::transaction_builder::TransactionBuilder;
use aptos_sdk::types::account_address::AccountAddress;
use aptos_sdk::types::chain_id::ChainId;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::types::{AccountKey, LocalAccount};
use once_cell::sync::Lazy;
use reqwest;
use serde::de::Unexpected::Str;
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::{stdin, stdout, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use aptos_sdk::rest_client::aptos_api_types::{Address};
use tokio;
use tokio::sync::mpsc;
use url::Url;
use dotenv::dotenv;


#[derive(Deserialize)]
struct AccountData {
    sequence_number: String,
}

async fn create_wallet(address: &str, priv_key: &str, seq_number: u64) -> LocalAccount {
    let account = LocalAccount::new(
        AccountAddress::from_str(address).unwrap(),
        AccountKey::from_private_key(Ed25519PrivateKey::from_encoded_string(priv_key).unwrap()),
        seq_number,
    );

    account
}
async fn get_account_sequence_number(address: &str, node_url: &str) -> u64 {
    let account_data = reqwest::get(format!("{node_url}v1/accounts/{address}"))
        .await
        .unwrap()
        .json::<AccountData>()
        .await
        .unwrap_or_else(|err| {
            println!("Account has 0 transactions");
            AccountData {
                sequence_number: String::from("0"),
            }
        });
    account_data.sequence_number.parse::<u64>().unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let transaction_fee: u64 = 54100;
    let node_env = std::env::var("NODE_URL").unwrap();
    let node_url: Url = Url::from_str(&node_env[..]).unwrap_or_else(|_| {
        println!("Use default node");
        return Url::from_str("https://aptos-mainnet.pontem.network").unwrap();
    });
    //Init data
    print!("To send: ");
    io::stdout().flush().expect("flush failed.");
    let mut to_address = String::new();
    io::stdin()
        .read_line(&mut to_address)
        .expect("Failed to read address");
    to_address = to_address.trim().parse()?;

    let mut wallets: Vec<LocalAccount> = vec![];
    let mut addresses = vec![];
    let mut priv_keys = vec![];
    let mut seqs = vec![];
    let mut addresses_data = String::new();
    File::open("addresses.txt")
        .expect("File with addresses not found!")
        .read_to_string(&mut addresses_data)
        .expect("Can't read addresses file to variable");

    let mut priv_keys_data = String::new();
    File::open("priv_keys.txt")
        .expect("File with private keys not found!")
        .read_to_string(&mut priv_keys_data)
        .expect("Can't read private keys file to variable");

    for (address, priv_key) in addresses_data.split("\n").zip(priv_keys_data.split("\n")) {
        if address == "" {
            continue;
        }
        addresses.push(address);
        priv_keys.push(priv_key);
        seqs.push(get_account_sequence_number(&address, &node_url.as_str()).await);
    }

    for i in 0..addresses.len() {
        println!(
            "Address: {:?}, private key: {:?}, seq: {:?}",
            addresses[i], priv_keys[i], seqs[i]
        );
    }

    for i in 0..addresses.len() {
        let wallet = create_wallet(addresses[i], priv_keys[i], seqs[i]).await;
        wallets.push(wallet);
    }

    println!("Wallets {:?}, len: {:?}", wallets, wallets.len());
    for mut wallet in wallets {
            let rest_client = Client::new(node_url.clone());
            let coin_client = CoinClient::new(&rest_client);
            let balance = coin_client
                .get_account_balance(&wallet.address())
                .await
                .unwrap();
            if balance < transaction_fee {
                println!("INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE. Account: {:?}", wallet.address());
            } else {
                let value = balance - transaction_fee;
                let txn_hash = coin_client.transfer(
                    &mut wallet,
                    AccountAddress::from_str(&to_address[..]).unwrap(),
                    value,
                    None,
                ).await.unwrap();
                println!("{:?}", txn_hash.hash);
            }
    }

    Ok(())
}
