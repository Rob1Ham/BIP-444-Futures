//! # Bitcoin Taproot Futures Contract
//!
//! Trustless speculation on BIP 444 UASF activation. BIP 444 makes OP_IF/OP_NOTIF
//! consensus-invalid in Taproot scripts. Leaf 1 contains these opcodes and becomes
//! unspendable if BIP 444 activates (YES wins). Leaf 2 remains valid (YES fallback).
//!
//! Spending paths:
//! - Leaf 1 Path A: 2-of-2 multisig (presigned settlement)
//! - Leaf 1 Path B: NO_ALT + after(100) - NO wins if BIP 444 fails
//! - Leaf 2: YES + after(200) - YES wins if BIP 444 activates
//!
//! Uses NUMS point internal key to enforce script-path spending only.

use bitcoin::{
    absolute::LockTime,
    address::Address,
    hashes::Hash,
    key::{Secp256k1, TapTweak},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, Network, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};
use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use bdk_esplora::EsploraExt;
use bdk_wallet::{
    bitcoin::bip32::DerivationPath,
    descriptor::Descriptor,
    keys::{
        bip39::{Language, Mnemonic},
        DerivableKey, ExtendedKey,
    },
    KeychainKind, Wallet,
};
use miniscript::{policy::Concrete, Miniscript, Tap};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, thread, time::Duration};

// ═══════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════

const NO_SPEND_HEIGHT: u32 = 100;
const YES_SPEND_HEIGHT: u32 = 200;
const SIGNET_NETWORK: Network = Network::Signet;
const FAUCET_URL: &str = "https://signet-faucet-koij.shuttle.app/get_testcoins";
const ESPLORA_URL: &str = "https://mempool.space/signet/api";

/// BIP 341 NUMS point - no known private key, forces script-path spending
const NUMS_POINT: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// ═══════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct FaucetRequest {
    address: String,
}

#[derive(Debug, Deserialize)]
struct FaucetResponse {
    txid: Option<String>,
    error: Option<String>,
}

/// Party with HD wallet and signing keys (m/86'/1'/0'/0/0 primary, m/86'/1'/1'/0/0 alt)
#[allow(dead_code)]
struct Party {
    name: String,
    wallet: Wallet,
    address: Address,
    pubkey: XOnlyPublicKey,
    keypair: bitcoin::key::Keypair,
    alt_keypair: Option<bitcoin::key::Keypair>,
    alt_pubkey: Option<XOnlyPublicKey>,
}

impl Party {
    /// Creates party with BIP-86 wallet and signing keypairs
    fn new(name: &str, mnemonic_phrase: &str, derive_alt: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)?;
        let xkey: ExtendedKey = mnemonic.into_extended_key()?;
        let xpriv = xkey.into_xprv(SIGNET_NETWORK).unwrap();

        // BIP-86 Taproot wallet descriptors
        let descriptor = format!("tr({}/86h/1h/0h/0/*)", xpriv);
        let change_descriptor = format!("tr({}/86h/1h/0h/1/*)", xpriv);
        let mut wallet = Wallet::create(descriptor, change_descriptor)
            .network(SIGNET_NETWORK)
            .create_wallet_no_persist()?;

        let address_info = wallet.reveal_next_address(KeychainKind::External);
        let address = address_info.address.clone();

        // Primary keypair at m/86'/1'/0'/0/0
        let path = DerivationPath::from_str("m/86'/1'/0'/0/0")?;
        let derived_xpriv = xpriv.derive_priv(&secp, &path)?;
        let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &derived_xpriv.private_key);
        let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);

        // Alternate keypair at m/86'/1'/1'/0/0 (for NO party's timelock path)
        let (alt_keypair, alt_pubkey) = if derive_alt {
            let alt_path = DerivationPath::from_str("m/86'/1'/1'/0/0")?;
            let alt_xpriv = xpriv.derive_priv(&secp, &alt_path)?;
            let alt_kp = bitcoin::key::Keypair::from_secret_key(&secp, &alt_xpriv.private_key);
            let (alt_pk, _) = XOnlyPublicKey::from_keypair(&alt_kp);
            (Some(alt_kp), Some(alt_pk))
        } else {
            (None, None)
        };

        Ok(Party {
            name: name.to_string(),
            wallet,
            address,
            pubkey,
            keypair,
            alt_keypair,
            alt_pubkey,
        })
    }
}

/// Taproot contract: Leaf 1 (multisig OR NO+timelock), Leaf 2 (YES+timelock)
#[allow(dead_code)]
struct Contract {
    address: Address,
    descriptor: Descriptor<String>,
    spend_info: TaprootSpendInfo,
    leaf1_script: ScriptBuf,
    leaf2_script: ScriptBuf,
}

/// BDK wallets for different spending paths (production would use PSBTs)
#[allow(dead_code)]
struct SigningWallets {
    yes_only: Wallet,   // Leaf 2
    no_only: Wallet,    // Leaf 1 Path B
    multisig: Wallet,   // Leaf 1 Path A
}

impl SigningWallets {
    /// Creates signing wallets with selective private key access per spending path
    fn new(
        yes_pk: XOnlyPublicKey,
        no_pk: XOnlyPublicKey,
        no_alt_pk: XOnlyPublicKey,
        yes_mnemonic: &str,
        no_mnemonic: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();

        let yes_mnem = Mnemonic::parse_in_normalized(Language::English, yes_mnemonic)?;
        let yes_xkey: ExtendedKey = yes_mnem.into_extended_key()?;
        let yes_xpriv = yes_xkey.into_xprv(SIGNET_NETWORK).unwrap();

        let no_mnem = Mnemonic::parse_in_normalized(Language::English, no_mnemonic)?;
        let no_xkey: ExtendedKey = no_mnem.into_extended_key()?;
        let no_xpriv = no_xkey.into_xprv(SIGNET_NETWORK).unwrap();

        let yes_path = DerivationPath::from_str("m/86'/1'/0'/0/0")?;
        let yes_derived = yes_xpriv.derive_priv(&secp, &yes_path)?;

        let no_path = DerivationPath::from_str("m/86'/1'/0'/0/0")?;
        let no_derived = no_xpriv.derive_priv(&secp, &no_path)?;

        let no_alt_path = DerivationPath::from_str("m/86'/1'/1'/0/0")?;
        let no_alt_derived = no_xpriv.derive_priv(&secp, &no_alt_path)?;

        let leaf1_policy_str = format!(
            "or(and(pk({}),pk({})),and(pk({}),after({})))",
            yes_pk, no_pk, no_alt_pk, NO_SPEND_HEIGHT
        );
        let leaf2_policy_str = format!("and(pk({}),after({}))", yes_pk, YES_SPEND_HEIGHT);

        let leaf1_policy: Concrete<XOnlyPublicKey> = leaf1_policy_str.parse()?;
        let leaf1_miniscript: Miniscript<XOnlyPublicKey, Tap> = leaf1_policy.compile()?;

        let leaf2_policy: Concrete<XOnlyPublicKey> = leaf2_policy_str.parse()?;
        let leaf2_miniscript: Miniscript<XOnlyPublicKey, Tap> = leaf2_policy.compile()?;

        let leaf1_ms_str = leaf1_miniscript.to_string();
        let leaf2_ms_str = leaf2_miniscript.to_string();

        let change_desc = format!("tr({})", NUMS_POINT);

        // YES-only wallet (has YES private key)
        let yes_only_leaf1 = leaf1_ms_str.clone();
        let yes_only_leaf2 = leaf2_ms_str.replace(&yes_pk.to_string(), &yes_derived.to_string());
        let yes_only_desc = format!("tr({},{{{},{}}})", NUMS_POINT, yes_only_leaf1, yes_only_leaf2);
        let yes_only = Wallet::create(yes_only_desc, change_desc.clone())
            .network(SIGNET_NETWORK)
            .create_wallet_no_persist()?;

        // NO-only wallet (has NO_ALT private key)
        let no_only_leaf1 = leaf1_ms_str
            .replace(&no_alt_pk.to_string(), &no_alt_derived.to_string());
        let no_only_leaf2 = leaf2_ms_str.clone();
        let no_only_desc = format!("tr({},{{{},{}}})", NUMS_POINT, no_only_leaf1, no_only_leaf2);
        let no_only = Wallet::create(no_only_desc, change_desc.clone())
            .network(SIGNET_NETWORK)
            .create_wallet_no_persist()?;

        // Multisig wallet (has YES and NO private keys)
        let multisig_leaf1 = leaf1_ms_str
            .replace(&yes_pk.to_string(), &yes_derived.to_string())
            .replace(&no_pk.to_string(), &no_derived.to_string())
            .replace(&no_alt_pk.to_string(), &no_alt_derived.to_string());
        let multisig_leaf2 = leaf2_ms_str.replace(&yes_pk.to_string(), &yes_derived.to_string());
        let multisig_desc = format!("tr({},{{{},{}}})", NUMS_POINT, multisig_leaf1, multisig_leaf2);
        let multisig = Wallet::create(multisig_desc, change_desc)
            .network(SIGNET_NETWORK)
            .create_wallet_no_persist()?;

        println!("\n✓ Created 3 signing wallets:");
        println!("  1. YES-only wallet (Leaf 2: YES + timelock)");
        println!("  2. NO-only wallet (Leaf 1 Path B: NO_ALT + timelock)");
        println!("  3. Multisig wallet (Leaf 1 Path A: YES + NO)");

        Ok(SigningWallets {
            yes_only,
            no_only,
            multisig,
        })
    }
}

impl Contract {
    /// Creates Taproot contract with two leaves and NUMS internal key
    ///
    /// BIP 444 futures contract: Leaf 1 contains OR (compiles to OP_IF) which becomes
    /// consensus-invalid if BIP 444 activates. Leaf 2 has no conditionals, remains valid.
    fn new(yes_pk: XOnlyPublicKey, no_pk: XOnlyPublicKey, no_alt_pk: XOnlyPublicKey) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();

        // Leaf 1: OR compiles to OP_IF/OP_NOTIF (becomes invalid under BIP 444)
        let leaf1_policy_str = format!(
            "or(and(pk({}),pk({})),and(pk({}),after({})))",
            yes_pk, no_pk, no_alt_pk, NO_SPEND_HEIGHT
        );
        // Leaf 2: No conditional opcodes (remains valid under BIP 444)
        let leaf2_policy_str = format!("and(pk({}),after({}))", yes_pk, YES_SPEND_HEIGHT);

        println!("Leaf 1 Policy: {}", leaf1_policy_str);
        println!("Leaf 2 Policy: {}", leaf2_policy_str);

        let leaf1_policy: Concrete<XOnlyPublicKey> = leaf1_policy_str.parse()?;
        let leaf1_miniscript: Miniscript<XOnlyPublicKey, Tap> = leaf1_policy.compile()?;
        let leaf1_script = leaf1_miniscript.encode();

        let leaf2_policy: Concrete<XOnlyPublicKey> = leaf2_policy_str.parse()?;
        let leaf2_miniscript: Miniscript<XOnlyPublicKey, Tap> = leaf2_policy.compile()?;
        let leaf2_script = leaf2_miniscript.encode();

        println!("\nLeaf 1 Miniscript: {}", leaf1_miniscript);
        println!("Leaf 2 Miniscript: {}", leaf2_miniscript);

        let nums_pk = XOnlyPublicKey::from_str(NUMS_POINT)?;
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(1, leaf1_script.clone())?
            .add_leaf(1, leaf2_script.clone())?;

        let spend_info = taproot_builder.finalize(&secp, nums_pk)
            .map_err(|e| format!("Taproot finalize failed: {:?}", e))?;

        let address = Address::p2tr_tweaked(spend_info.output_key(), SIGNET_NETWORK);

        let descriptor_str = format!(
            "tr({},{{{},{}}})",
            NUMS_POINT,
            leaf1_miniscript,
            leaf2_miniscript
        );
        println!("\nDescriptor: {}", descriptor_str);

        let descriptor: Descriptor<String> = descriptor_str.parse()?;

        println!("\n=== SPENDING PATHS ===");
        println!("Leaf 1 - Path A (Multisig): pk(YES) AND pk(NO)");
        println!("Leaf 1 - Path B (Timelock): pk(NO_ALT) AND after({})", NO_SPEND_HEIGHT);
        println!("Leaf 2 (YES Timelock): pk(YES) AND after({})", YES_SPEND_HEIGHT);

        Ok(Contract {
            address,
            descriptor,
            spend_info,
            leaf1_script,
            leaf2_script,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/// Requests test bitcoins from Signet faucet
fn request_faucet(address: &Address) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .no_proxy()
        .build()?;
    println!("Requesting faucet for: {}", address);
    let req = FaucetRequest { address: address.to_string() };
    let response = client.post(FAUCET_URL).json(&req).send()?.json::<FaucetResponse>()?;

    if let Some(txid) = response.txid {
        println!("✓ Faucet TXID: {}", txid);
        Ok(txid)
    } else {
        Err(format!("Faucet error: {:?}", response.error).into())
    }
}

/// Broadcasts transaction to Signet via Esplora API
fn broadcast_tx(tx: &Transaction) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .no_proxy()
        .build()?;
    let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
    println!("\nBroadcasting transaction...");

    let url = format!("{}/tx", ESPLORA_URL);
    let response = client.post(&url).body(tx_hex).send()?;

    if response.status().is_success() {
        let txid = response.text()?;
        println!("✓ Broadcast successful: {}", txid);
        Ok(txid)
    } else {
        let error = response.text()?;
        Err(format!("Broadcast failed: {}", error).into())
    }
}

/// Queries current block height from Signet
#[allow(dead_code)]
fn get_current_block_height() -> Result<u32, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .no_proxy()
        .build()?;
    let url = format!("{}/blocks/tip/height", ESPLORA_URL);
    let height: u32 = client.get(&url).send()?.text()?.parse()?;
    println!("Current block height: {}", height);
    Ok(height)
}


// ═══════════════════════════════════════════════════════════════
// MAIN - BIP 444 UASF Futures Contract Demonstration
// ═══════════════════════════════════════════════════════════════
// Demonstrates trustless speculation on BIP 444 activation.
// If BIP 444 activates: Leaf 1 (with OP_IF) becomes invalid → YES wins
// If BIP 444 fails: NO spends via Leaf 1 before YES timelock

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔════════════════════════════════════════════════════╗");
    println!("║   BIP 444 UASF Futures Contract (Signet Demo)     ║");
    println!("╚════════════════════════════════════════════════════╝\n");

    // ═══ STEP 1: CREATE WALLETS ═══
    println!("Step 1: Creating wallets...");
    let mut yes_party = Party::new("YES", "jeans ".repeat(12).trim(), false)?;
    println!("✓ YES: {}", yes_party.address);

    let mut no_party = Party::new("NO", "blue ".repeat(12).trim(), true)?;
    println!("✓ NO: {}", no_party.address);
    println!("  NO alt pubkey: {}", no_party.alt_pubkey.unwrap());

    // ═══ STEP 2: CREATE CONTRACT ═══
    println!("\nStep 2: Creating taproot contract...");
    let contract = Contract::new(
        yes_party.pubkey,
        no_party.pubkey,
        no_party.alt_pubkey.unwrap(),
    )?;
    println!("✓ Contract address: {}", contract.address);

    // ═══ CREATE SIGNING WALLETS ═══
    println!("\nCreating signing wallets for different spending paths...");
    let _signing_wallets = SigningWallets::new(
        yes_party.pubkey,
        no_party.pubkey,
        no_party.alt_pubkey.unwrap(),
        "jeans ".repeat(12).trim(),
        "blue ".repeat(12).trim(),
    )?;
    println!("\nNOTE: Production would use BDK's PSBT signing. This demo");
    println!("uses manual signatures to show cryptographic details.");

    // ═══ STEP 3: FUND WALLETS ═══
    println!("\nStep 3: Requesting faucet funds...");
    println!("(Note: Faucet may be rate-limited)");
    request_faucet(&yes_party.address)?;
    thread::sleep(Duration::from_secs(3));
    request_faucet(&no_party.address)?;
    println!("Waiting 3 seconds for faucet transactions to propagate...");
    thread::sleep(Duration::from_secs(3));

    // ═══ STEP 4: ATOMIC FUNDING ═══
    println!("\nStep 4: Syncing wallets and creating atomic funding transaction...");
    let esplora = EsploraBuilder::new(ESPLORA_URL).build_blocking();

    println!("\nSyncing YES wallet...");
    let yes_sync_request = yes_party.wallet.start_sync_with_revealed_spks();
    let yes_update = esplora.sync(yes_sync_request, 5)?;
    yes_party.wallet.apply_update(yes_update)?;
    let yes_balance = yes_party.wallet.balance();
    println!("✓ YES balance: {} sats (spendable: {})",
        yes_balance.total(), yes_balance.confirmed + yes_balance.trusted_pending);

    println!("\nSyncing NO wallet...");
    let no_sync_request = no_party.wallet.start_sync_with_revealed_spks();
    let no_update = esplora.sync(no_sync_request, 5)?;
    no_party.wallet.apply_update(no_update)?;
    let no_balance = no_party.wallet.balance();
    println!("✓ NO balance: {} sats (spendable: {})",
        no_balance.total(), no_balance.confirmed + no_balance.trusted_pending);

    let yes_spendable = yes_balance.confirmed + yes_balance.trusted_pending;
    let no_spendable = no_balance.confirmed + no_balance.trusted_pending;
    let fee_buffer = Amount::from_sat(1000);
    let yes_amount = yes_spendable.checked_sub(fee_buffer).unwrap_or(Amount::ZERO);
    let no_amount = no_spendable.checked_sub(fee_buffer).unwrap_or(Amount::ZERO);
    let contribution_amount = std::cmp::min(yes_amount, no_amount);
    println!("\n✓ Equal contribution amount: {} sats per party", contribution_amount.to_sat());

    println!("\nBuilding atomic funding transaction (2 inputs, 1 output)...");

    let yes_utxos: Vec<_> = yes_party.wallet.list_unspent().collect();
    let no_utxos: Vec<_> = no_party.wallet.list_unspent().collect();

    if yes_utxos.is_empty() || no_utxos.is_empty() {
        return Err("Insufficient UTXOs for atomic funding".into());
    }

    let yes_utxo = &yes_utxos[0];
    let no_utxo = &no_utxos[0];

    let total_input = yes_utxo.txout.value.to_sat() + no_utxo.txout.value.to_sat();
    let output_amount = total_input - 500;

    let mut funding_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: yes_utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: no_utxo.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: contract.address.script_pubkey(),
        }],
    };

    // Sign with BIP-86 key-path spending (tweaked keys)
    let (sig_yes, sig_no) = {
        let secp = Secp256k1::new();
        let prevouts = vec![yes_utxo.txout.clone(), no_utxo.txout.clone()];
        let prevouts_ref = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&funding_tx);

        let yes_tweaked_keypair = yes_party.keypair.tap_tweak(&secp, None);
        let no_tweaked_keypair = no_party.keypair.tap_tweak(&secp, None);

        let sighash_yes = sighash_cache.taproot_key_spend_signature_hash(
            0, &prevouts_ref, TapSighashType::Default
        )?;
        let msg_yes = bitcoin::secp256k1::Message::from_digest(*sighash_yes.as_byte_array());
        let sig_yes = secp.sign_schnorr(&msg_yes, &yes_tweaked_keypair.to_keypair());

        let sighash_no = sighash_cache.taproot_key_spend_signature_hash(
            1, &prevouts_ref, TapSighashType::Default
        )?;
        let msg_no = bitcoin::secp256k1::Message::from_digest(*sighash_no.as_byte_array());
        let sig_no = secp.sign_schnorr(&msg_no, &no_tweaked_keypair.to_keypair());

        (sig_yes, sig_no)
    };

    let mut witness_yes = Witness::new();
    witness_yes.push(sig_yes.as_ref());
    funding_tx.input[0].witness = witness_yes;

    let mut witness_no = Witness::new();
    witness_no.push(sig_no.as_ref());
    funding_tx.input[1].witness = witness_no;

    println!("✓ Atomic funding transaction created:");
    println!("  Input 0 (YES): {} sats", yes_utxo.txout.value.to_sat());
    println!("  Input 1 (NO): {} sats", no_utxo.txout.value.to_sat());
    println!("  Output (Contract): {} sats", output_amount);

    let funding_txid = broadcast_tx(&funding_tx)?;
    println!("\n✓ Atomic funding complete! TXID: {}", funding_txid);

    println!("\nWaiting for contract UTXO...");
    thread::sleep(Duration::from_secs(10));

    // ═══ STEP 5: MULTISIG SPEND (Leaf 1 Path A) ═══
    // Self-send simulates BIP 444 grandfather clause (UTXOs before activation exempt)
    println!("\nStep 5: Self-send transaction (multisig leaf)...");
    println!("└─ Using: Multisig Signing Wallet (Leaf 1 Path A)");

    let utxo_value = output_amount;
    let vout = 0u32;
    let secp = Secp256k1::new();

    let prev_txid = bitcoin::Txid::from_str(&funding_txid)?;
    let input = TxIn {
        previous_output: bitcoin::OutPoint { txid: prev_txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let output_value = utxo_value - 300;
    let output = TxOut {
        value: Amount::from_sat(output_value),
        script_pubkey: contract.address.script_pubkey(),
    };

    let mut self_send_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Sign with script-path (untweaked keys, requires control block)
    {
        let prevout = TxOut {
            value: Amount::from_sat(utxo_value),
            script_pubkey: contract.address.script_pubkey(),
        };
        let prevouts = Prevouts::All(&[prevout]);
        let mut sighash_cache = SighashCache::new(&mut self_send_tx);

        let control_block = contract.spend_info
            .control_block(&(contract.leaf1_script.clone(), LeafVersion::TapScript))
            .expect("control block");

        let leaf_hash = TapLeafHash::from_script(&contract.leaf1_script, LeafVersion::TapScript);

        let sighash = sighash_cache.taproot_script_spend_signature_hash(
            0, &prevouts, leaf_hash, TapSighashType::Default
        )?;
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());

        let sig_yes = secp.sign_schnorr(&msg, &yes_party.keypair);
        let sig_no = secp.sign_schnorr(&msg, &no_party.keypair);

        let mut witness = Witness::new();
        witness.push(sig_no.as_ref());
        witness.push(sig_yes.as_ref());
        witness.push(contract.leaf1_script.as_bytes());
        witness.push(control_block.serialize());
        self_send_tx.input[0].witness = witness;
    }

    println!("✓ Self-send signed (YES & NO multisig)");
    let self_send_txid = broadcast_tx(&self_send_tx)?;

    // ═══ STEP 6: SECOND FUNDING - NO TIMELOCK PATH ═══
    println!("\n═══════════════════════════════════════════════════════");
    println!("Step 6: Second funding round for NO timelock path");
    println!("═══════════════════════════════════════════════════════");

    println!("\nRequesting more faucet funds for second round...");
    request_faucet(&yes_party.address)?;
    thread::sleep(Duration::from_secs(3));
    request_faucet(&no_party.address)?;
    println!("Waiting for faucet transactions to propagate...");
    thread::sleep(Duration::from_secs(10));

    // Sync wallets again
    println!("\nSyncing wallets for second funding round...");
    let yes_sync_request2 = yes_party.wallet.start_sync_with_revealed_spks();
    let yes_update2 = esplora.sync(yes_sync_request2, 5)?;
    yes_party.wallet.apply_update(yes_update2)?;

    let no_sync_request2 = no_party.wallet.start_sync_with_revealed_spks();
    let no_update2 = esplora.sync(no_sync_request2, 5)?;
    no_party.wallet.apply_update(no_update2)?;

    // Get fresh UTXOs
    let yes_utxos2: Vec<_> = yes_party.wallet.list_unspent().collect();
    let no_utxos2: Vec<_> = no_party.wallet.list_unspent().collect();

    if yes_utxos2.len() < 2 || no_utxos2.len() < 2 {
        return Err("Insufficient UTXOs for second funding round".into());
    }

    // Use second UTXO from each party
    let yes_utxo2 = &yes_utxos2[1];
    let no_utxo2 = &no_utxos2[1];

    let total_input2 = yes_utxo2.txout.value.to_sat() + no_utxo2.txout.value.to_sat();
    let output_amount2 = total_input2 - 500;

    let mut funding_tx2 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: yes_utxo2.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: no_utxo2.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount2),
            script_pubkey: contract.address.script_pubkey(),
        }],
    };

    // Sign second funding transaction
    let (sig_yes2, sig_no2) = {
        let secp = Secp256k1::new();
        let prevouts2 = vec![yes_utxo2.txout.clone(), no_utxo2.txout.clone()];
        let prevouts_ref2 = Prevouts::All(&prevouts2);
        let mut sighash_cache2 = SighashCache::new(&funding_tx2);

        let yes_tweaked_keypair = yes_party.keypair.tap_tweak(&secp, None);
        let no_tweaked_keypair = no_party.keypair.tap_tweak(&secp, None);

        let sighash_yes = sighash_cache2.taproot_key_spend_signature_hash(
            0, &prevouts_ref2, TapSighashType::Default
        )?;
        let msg_yes = bitcoin::secp256k1::Message::from_digest(*sighash_yes.as_byte_array());
        let sig_yes = secp.sign_schnorr(&msg_yes, &yes_tweaked_keypair.to_keypair());

        let sighash_no = sighash_cache2.taproot_key_spend_signature_hash(
            1, &prevouts_ref2, TapSighashType::Default
        )?;
        let msg_no = bitcoin::secp256k1::Message::from_digest(*sighash_no.as_byte_array());
        let sig_no = secp.sign_schnorr(&msg_no, &no_tweaked_keypair.to_keypair());

        (sig_yes, sig_no)
    };

    let mut witness_yes2 = Witness::new();
    witness_yes2.push(sig_yes2.as_ref());
    funding_tx2.input[0].witness = witness_yes2;

    let mut witness_no2 = Witness::new();
    witness_no2.push(sig_no2.as_ref());
    funding_tx2.input[1].witness = witness_no2;

    println!("✓ Second atomic funding transaction created");
    let funding_txid2 = broadcast_tx(&funding_tx2)?;
    println!("✓ Second funding complete! TXID: {}", funding_txid2);

    println!("\nWaiting for contract UTXO...");
    thread::sleep(Duration::from_secs(10));

    // ═══ NO TIMELOCK SPEND (Leaf 1 Path B) ═══
    println!("\n--- Leaf 1, Path B: NO Timelock Spend ---");
    println!("Policy: and(pk(NO_ALT), after({}))", NO_SPEND_HEIGHT);
    println!("└─ Using: NO-only Signing Wallet");

    let mut no_timelock_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(NO_SPEND_HEIGHT).expect("valid height"),
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&funding_txid2)?,
                vout: 0
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount2 - 300),
            script_pubkey: no_party.address.script_pubkey(),
        }],
    };

    // Sign using NO_ALT key, empty push selects OR branch
    {
        let prevout = TxOut {
            value: Amount::from_sat(output_amount2),
            script_pubkey: contract.address.script_pubkey(),
        };
        let prevouts = Prevouts::All(&[prevout]);
        let mut sighash_cache = SighashCache::new(&mut no_timelock_tx);

        let control_block = contract.spend_info
            .control_block(&(contract.leaf1_script.clone(), LeafVersion::TapScript))
            .expect("control block");
        let leaf_hash = TapLeafHash::from_script(&contract.leaf1_script, LeafVersion::TapScript);

        let sighash = sighash_cache.taproot_script_spend_signature_hash(
            0, &prevouts, leaf_hash, TapSighashType::Default
        )?;
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());

        let sig = secp.sign_schnorr(&msg, &no_party.alt_keypair.unwrap());

        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        witness.push(&[]);  // Empty push selects OR branch
        witness.push(contract.leaf1_script.as_bytes());
        witness.push(control_block.serialize());
        no_timelock_tx.input[0].witness = witness;
    }

    println!("✓ NO timelock transaction signed");
    let current_height = get_current_block_height()?;
    if current_height >= NO_SPEND_HEIGHT {
        println!("✓ Block height sufficient, broadcasting...");
        let no_spend_txid = broadcast_tx(&no_timelock_tx)?;
        println!("✓ NO timelock spend complete! TXID: {}", no_spend_txid);
    } else {
        println!("⚠ Current height {} < required {}", current_height, NO_SPEND_HEIGHT);
        println!("  Transaction ready but cannot broadcast until timelock expires");
        println!("  TXID (ready): {}", no_timelock_tx.compute_txid());
    }

    // ═══ STEP 7: THIRD FUNDING - YES TIMELOCK PATH ═══
    println!("\n═══════════════════════════════════════════════════════");
    println!("Step 7: Third funding round for YES timelock path");
    println!("═══════════════════════════════════════════════════════");

    println!("\nRequesting more faucet funds for third round...");
    request_faucet(&yes_party.address)?;
    thread::sleep(Duration::from_secs(3));
    request_faucet(&no_party.address)?;
    println!("Waiting for faucet transactions to propagate...");
    thread::sleep(Duration::from_secs(10));

    // Sync wallets again
    println!("\nSyncing wallets for third funding round...");
    let yes_sync_request3 = yes_party.wallet.start_sync_with_revealed_spks();
    let yes_update3 = esplora.sync(yes_sync_request3, 5)?;
    yes_party.wallet.apply_update(yes_update3)?;

    let no_sync_request3 = no_party.wallet.start_sync_with_revealed_spks();
    let no_update3 = esplora.sync(no_sync_request3, 5)?;
    no_party.wallet.apply_update(no_update3)?;

    // Get fresh UTXOs
    let yes_utxos3: Vec<_> = yes_party.wallet.list_unspent().collect();
    let no_utxos3: Vec<_> = no_party.wallet.list_unspent().collect();

    if yes_utxos3.len() < 3 || no_utxos3.len() < 3 {
        return Err("Insufficient UTXOs for third funding round".into());
    }

    // Use third UTXO from each party
    let yes_utxo3 = &yes_utxos3[2];
    let no_utxo3 = &no_utxos3[2];

    let total_input3 = yes_utxo3.txout.value.to_sat() + no_utxo3.txout.value.to_sat();
    let output_amount3 = total_input3 - 500;

    let mut funding_tx3 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: yes_utxo3.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: no_utxo3.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount3),
            script_pubkey: contract.address.script_pubkey(),
        }],
    };

    // Sign third funding transaction
    let (sig_yes3, sig_no3) = {
        let secp = Secp256k1::new();
        let prevouts3 = vec![yes_utxo3.txout.clone(), no_utxo3.txout.clone()];
        let prevouts_ref3 = Prevouts::All(&prevouts3);
        let mut sighash_cache3 = SighashCache::new(&funding_tx3);

        let yes_tweaked_keypair = yes_party.keypair.tap_tweak(&secp, None);
        let no_tweaked_keypair = no_party.keypair.tap_tweak(&secp, None);

        let sighash_yes = sighash_cache3.taproot_key_spend_signature_hash(
            0, &prevouts_ref3, TapSighashType::Default
        )?;
        let msg_yes = bitcoin::secp256k1::Message::from_digest(*sighash_yes.as_byte_array());
        let sig_yes = secp.sign_schnorr(&msg_yes, &yes_tweaked_keypair.to_keypair());

        let sighash_no = sighash_cache3.taproot_key_spend_signature_hash(
            1, &prevouts_ref3, TapSighashType::Default
        )?;
        let msg_no = bitcoin::secp256k1::Message::from_digest(*sighash_no.as_byte_array());
        let sig_no = secp.sign_schnorr(&msg_no, &no_tweaked_keypair.to_keypair());

        (sig_yes, sig_no)
    };

    let mut witness_yes3 = Witness::new();
    witness_yes3.push(sig_yes3.as_ref());
    funding_tx3.input[0].witness = witness_yes3;

    let mut witness_no3 = Witness::new();
    witness_no3.push(sig_no3.as_ref());
    funding_tx3.input[1].witness = witness_no3;

    println!("✓ Third atomic funding transaction created");
    let funding_txid3 = broadcast_tx(&funding_tx3)?;
    println!("✓ Third funding complete! TXID: {}", funding_txid3);

    println!("\nWaiting for contract UTXO...");
    thread::sleep(Duration::from_secs(10));

    // ═══ YES TIMELOCK SPEND (Leaf 2) ═══
    println!("\n--- Leaf 2: YES Timelock Spend ---");
    println!("Policy: and(pk(YES), after({}))", YES_SPEND_HEIGHT);
    println!("└─ Using: YES-only Signing Wallet");

    let mut yes_timelock_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(YES_SPEND_HEIGHT).expect("valid height"),
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&funding_txid3)?,
                vout: 0
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount3 - 500),
            script_pubkey: yes_party.address.script_pubkey(),
        }],
    };

    // Sign with YES key (Leaf 2 - simpler, no branching)
    {
        let prevout = TxOut {
            value: Amount::from_sat(output_amount3),
            script_pubkey: contract.address.script_pubkey(),
        };
        let prevouts = Prevouts::All(&[prevout]);
        let mut sighash_cache = SighashCache::new(&mut yes_timelock_tx);

        let control_block = contract.spend_info
            .control_block(&(contract.leaf2_script.clone(), LeafVersion::TapScript))
            .expect("control block");
        let leaf_hash = TapLeafHash::from_script(&contract.leaf2_script, LeafVersion::TapScript);

        let sighash = sighash_cache.taproot_script_spend_signature_hash(
            0, &prevouts, leaf_hash, TapSighashType::Default
        )?;
        let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());

        let sig = secp.sign_schnorr(&msg, &yes_party.keypair);

        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        witness.push(contract.leaf2_script.as_bytes());
        witness.push(control_block.serialize());
        yes_timelock_tx.input[0].witness = witness;
    }

    println!("✓ YES timelock transaction signed");
    let current_height2 = get_current_block_height()?;
    if current_height2 >= YES_SPEND_HEIGHT {
        println!("✓ Block height sufficient, broadcasting...");
        let yes_spend_txid = broadcast_tx(&yes_timelock_tx)?;
        println!("✓ YES timelock spend complete! TXID: {}", yes_spend_txid);
    } else {
        println!("⚠ Current height {} < required {}", current_height2, YES_SPEND_HEIGHT);
        println!("  Transaction ready but cannot broadcast until timelock expires");
        println!("  TXID (ready): {}", yes_timelock_tx.compute_txid());
    }

    println!("\n╔════════════════════════════════════════════════════╗");
    println!("║              ✓ ALL STEPS COMPLETE                 ║");
    println!("╚════════════════════════════════════════════════════╝");

    println!("\n═══ PATH A: MULTISIG ═══");
    println!("  TXID: {}", self_send_txid);

    println!("\n═══ PATH B: NO TIMELOCK ═══");
    println!("  Funding: {}", funding_txid2);
    println!("  Status: {}", if current_height >= NO_SPEND_HEIGHT {
        "Broadcast successful"
    } else {
        "Ready (locked until block height)"
    });

    println!("\n═══ PATH C: YES TIMELOCK ═══");
    println!("  Funding: {}", funding_txid3);
    println!("  Status: {}", if current_height2 >= YES_SPEND_HEIGHT {
        "Broadcast successful"
    } else {
        "Ready (locked until block height)"
    });

    println!("\nContract: {}", contract.address);
    println!("Current height: {} | NO unlock: {} | YES unlock: {}",
        current_height2, NO_SPEND_HEIGHT, YES_SPEND_HEIGHT);

    Ok(())
}
