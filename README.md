# Bitcoin Taproot Futures Contract

Trustless on-chain futures contract for speculating on BIP 444 UASF activation.

## BIP 444 Context

**BIP 444** is a proposed UASF that makes `OP_IF` and `OP_NOTIF` consensus-invalid within Taproot script paths after activation. This contract enables trustless speculation on whether BIP 444 will activate:

- **YES Party**: Believes BIP 444 will activate
- **NO Party**: Believes BIP 444 will not activate

### Contract Mechanism

The contract leverages Taproot with three leaves:

**Leaf 1**: `or(and(YES, NO), and(NO_ALT, after(100)))`
- Contains `OP_IF`/`OP_NOTIF` opcodes (via miniscript `or`)
- **Will become unspendable** if BIP 444 activates
- Paths:
  - 2-of-2 multisig (for presigned collaborative settlement)
  - NO unilateral after block 100

**Leaf 2**: `and(YES, after(200))`
- No conditional opcodes, remains valid regardless of BIP 444
- YES unilateral after block 200 (later than Leaf 1)

**Leaf 3**: `and(YES, NO)` - **Refresh Transaction Path**
- Simple 2-of-2 multisig with no timelock or conditional opcodes
- **Critical for BIP 444 grandfather clause**: Allows cooperative "refresh" transaction
- BIP 444 exempts UTXOs created before activation; this path creates fresh UTXOs subject to new rules
- Most efficient spending path (shallowest in Taproot tree, smallest witness)
- Remains valid regardless of BIP 444 activation

**Settlement Logic**:
- If BIP 444 activates → Leaf 1 invalid → YES wins via Leaf 2
- If BIP 444 fails → NO spends via Leaf 1 before YES timelock expires
- **Refresh transaction** → Both parties cooperate via Leaf 3 to create fresh UTXO (bypasses grandfather clause)

Uses NUMS point internal key to enforce script-path-only spending.

## Implementation Details

### Refresh Transaction (Leaf 3)
BIP 444 includes a **grandfather clause**: UTXOs existing before activation are exempt from the new consensus rules.

Leaf 3 provides a cooperative 2-of-2 multisig path that enables a "refresh" transaction. After BIP 444 activates, both parties can cooperatively spend the grandfathered UTXO back to the same contract address, creating a **fresh UTXO that IS subject to BIP 444 rules**. This ensures the contract operates under the intended speculation mechanism rather than being perpetually exempt.

The demonstration uses a self-send transaction via Leaf 3 to show this refresh capability.

### Dual NO Keys
NO party uses two separate keys (`NO` and `NO_ALT`) because miniscript prohibits duplicate public keys in the same script execution path. Leaf 1 requires NO to potentially sign for both the multisig path and the timelock path.

### Testing Parameters
- Block heights (100, 200) are for testing on Signet
- Demonstrates contract mechanics without waiting for real UASF activation
- Production deployment would use actual BIP 444 activation height

### Demonstrated Spending Paths

The program demonstrates all three tapleaf spending paths:

1. **Leaf 3 - Refresh Transaction** (Step 5)
   - Cooperative 2-of-2 multisig
   - Bypasses BIP 444 grandfather clause
   - Creates fresh UTXO subject to new consensus rules
   - Most efficient path (smallest witness)

2. **Leaf 1 Path B - NO Timelock** (Step 6)
   - NO_ALT + after(100)
   - Contains OP_IF (becomes invalid if BIP 444 activates)
   - NO party's winning path if BIP 444 fails

3. **Leaf 2 - YES Timelock** (Step 7)
   - YES + after(200)
   - No OP_IF (remains valid regardless)
   - YES party's winning path if BIP 444 activates

### Key Features
- Atomic funding (2-input, 1-output)
- BIP-86 Taproot descriptors
- Script-path spending with control blocks
- Timelock transactions (nLockTime + nSequence)
- Refresh transaction capability to bypass grandfather clause

## Building and Running

```bash
cargo build
cargo run
```

## Configuration

Modify timelock heights in `src/main.rs`:
```rust
const NO_SPEND_HEIGHT: u32 = 100;
const YES_SPEND_HEIGHT: u32 = 200;
```

## Production Considerations

For mainnet deployment, proper implementation would require:

1. **Pre-sign Transaction Tree**: Build unsigned transaction tree from resolution backwards to funding
2. **UTXO Pre-allocation**: Identify and lock funding UTXOs before presigning
3. **Atomic Funding**: Both parties sign 2-input-1-output funding transaction simultaneously
4. **Refresh Transaction Strategy**:
   - Presign Leaf 3 (2-of-2) transaction for post-activation refresh
   - Execute refresh after BIP 444 activates to bypass grandfather clause
   - Creates fresh UTXO subject to BIP 444 consensus rules
5. **Collaborative Settlement**: Presign settlement transactions for all valid paths
6. **Security Review**: Comprehensive audit before mainnet deployment

## External Services

- Faucet: https://signet-faucet-koij.shuttle.app/get_testcoins
- Explorer: https://mempool.space/signet/api

## Disclaimer

⚠️ **This is demonstration code for educational purposes only.**

- Not production-ready or security-reviewed
- Uses deterministic mnemonics on Signet testnet
- Evaluate contract mechanics before mainnet consideration
- Consult legal and technical experts before deployment

## License

MIT

