# Bitcoin Taproot Futures Contract

Trustless on-chain futures contract for speculating on BIP 444 UASF activation.

## BIP 444 Context

**BIP 444** is a proposed UASF that makes `OP_IF` and `OP_NOTIF` consensus-invalid within Taproot script paths after activation. This contract enables trustless speculation on whether BIP 444 will activate:

- **YES Party**: Believes BIP 444 will activate
- **NO Party**: Believes BIP 444 will not activate

### Contract Mechanism

The contract leverages Taproot with two leaves:

**Leaf 1**: `or(and(YES, NO), and(NO_ALT, after(100)))`
- Contains `OP_IF`/`OP_NOTIF` opcodes (via miniscript `or`)
- **Will become unspendable** if BIP 444 activates
- Paths:
  - 2-of-2 multisig (for presigned collaborative settlement)
  - NO unilateral after block 100

**Leaf 2**: `and(YES, after(200))`
- No conditional opcodes, remains valid regardless of BIP 444
- YES unilateral after block 200 (later than Leaf 1)

**Settlement Logic**:
- If BIP 444 activates → Leaf 1 invalid → YES wins via Leaf 2
- If BIP 444 fails → NO spends via Leaf 1 before YES timelock expires

Uses NUMS point internal key to enforce script-path-only spending.

## Implementation Details

### Self-Send Transaction
BIP 444 includes a grandfather clause for UTXOs existing before activation. This implementation demonstrates a self-send transaction to the same contract address, simulating the creation of a "fresh" UTXO that would be subject to BIP 444 rules.

### Dual NO Keys
NO party uses two separate keys (`NO` and `NO_ALT`) because miniscript prohibits duplicate public keys in the same script execution path. Leaf 1 requires NO to potentially sign for both the multisig path and the timelock path.

### Testing Parameters
- Block heights (100, 200) are for testing on Signet
- Demonstrates contract mechanics without waiting for real UASF activation
- Production deployment would use actual BIP 444 activation height

### Key Features
- Atomic funding (2-input, 1-output)
- BIP-86 Taproot descriptors
- Script-path spending with control blocks
- Timelock transactions (nLockTime + nSequence)

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
4. **Collaborative Settlement**: Presign 2-of-2 multisig transaction for post-activation settlement
5. **Security Review**: Comprehensive audit before mainnet deployment

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

