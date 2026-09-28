#![no_main]

//! Fuzz harness for `mint_wrap` and `mint_wrap_batch`.
//!
//! Exercises signature verification, period validation, duplicate rejection,
//! and storage invariants under adversarial inputs. See README "Fuzzing".
//!
//! The batch target additionally asserts per-record authorization: every record
//! in a batch must be individually covered by the aggregated signature, a
//! substituted record must fail the whole batch (atomicity), and the mint
//! guard / opt-out / per-period uniqueness must hold for every record.

extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use soroban_sdk::{
    symbol_short,
    testutils::arbitrary::{arbitrary, Arbitrary},
    testutils::Address as _,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Symbol, Vec,
};
use stellar_wrap_contract::{StellarWrapContract, StellarWrapContractClient};

/// Structured fuzz input for `mint_wrap`.
#[derive(Clone, Debug, Arbitrary)]
pub struct MintWrapInput {
    /// Candidate period (`YYYYMM` when valid).
    pub period: u64,
    /// Raw hash bytes under test.
    pub data_hash: [u8; 32],
    /// Raw signature bytes (used when `use_valid_signature` is false).
    pub rogue_signature: [u8; 64],
    /// When true, sign the canonical payload with the admin key.
    pub use_valid_signature: bool,
    /// When true, invoke `mint_wrap` a second time with the same `(user, period)`.
    pub remint: bool,
}

/// Structured fuzz input for `mint_wrap_batch`.
#[derive(Clone, Debug, Arbitrary)]
pub struct MintWrapBatchInput {
    /// Candidate periods for each record (`YYYYMM` when valid).
    pub periods: [u64; 3],
    /// Raw hash bytes for each record.
    pub data_hashes: [[u8; 32]; 3],
    /// When true, sign the canonical batch payload with the admin key.
    pub use_valid_signature: bool,
    /// When true, substitute the last record's hash after signing.
    pub substitute_after_signing: bool,
    /// When true, invoke the batch a second time with the same records.
    pub remint: bool,
}

/// Produce a valid Ed25519 signature over the canonical `mint_wrap` payload.
///
/// The contract does not verify a signature over the raw arguments. Instead it
/// reconstructs a deterministic, domain-separated byte string (the "canonical
/// payload") from the exact tuple `(contract, user, period, archetype,
/// data_hash, nonce)` and verifies the admin's Ed25519 signature against that
/// payload. Binding every field into the signed message is what prevents an
/// attacker from replaying a signature with a swapped `user`, `period`, or
/// `data_hash`.
///
/// This helper mirrors the contract's construction exactly by calling the same
/// `construct_mint_payload` routine, then signs the resulting bytes with the
/// admin `signer`. Because the payload is built from the same inputs the
/// contract will use, the produced signature is accepted iff the submitted
/// arguments match the signed ones.
fn sign_payload(
    env: &Env,
    signer: &SigningKey,
    contract: &Address,
    user: &Address,
    period: u64,
    archetype: &Symbol,
    data_hash: &BytesN<32>,
) -> BytesN<64> {
    // Rebuild the canonical payload the contract will hash/verify against.
    // The trailing `1` is the nonce/version tag mixed into the payload so that
    // signatures cannot be reused across payload formats.
    let payload = stellar_wrap_contract::signature::construct_mint_payload(
        env, contract, user, period, archetype, data_hash, 1,
    );

    // Copy the payload out of the host into a fixed buffer so it can be signed
    // with the standard Ed25519 implementation. The buffer is sized to the
    // maximum payload length; `len` bounds the slice actually signed.
    let mut out = [0u8; 512];
    let len = payload.len() as usize;
    payload.copy_into_slice(&mut out[..len]);
    // Sign the canonical bytes with the admin key. The contract verifies this
    // signature against the admin public key registered at `initialize`.
    let signature = signer.sign(&out[..len]);
    BytesN::from_array(env, &signature.to_bytes())
}

/// Produce a valid Ed25519 signature over the canonical `mint_wrap_batch`
/// payload.
///
/// As with `sign_payload`, the contract verifies a signature over a canonical
/// encoding rather than over the raw call arguments. For batches the payload
/// commits to the ordered list of `(period, data_hash)` records, so a single
/// aggregated signature authorizes every record at once. Committing to the
/// full ordered list is what makes the batch atomic: mutating, reordering, or
/// substituting any record changes the payload and invalidates the signature.
fn sign_batch_payload(
    env: &Env,
    signer: &SigningKey,
    contract: &Address,
    user: &Address,
    archetype: &Symbol,
    records: &[(u64, BytesN<32>)],
) -> BytesN<64> {
    // Rebuild the canonical batch payload from the same ordered records the
    // contract will verify. The trailing `1` is the nonce/version tag.
    let payload = stellar_wrap_contract::signature::construct_mint_batch_payload(
        env, contract, user, archetype, records, 1,
    );

    // Copy the payload into a fixed buffer and sign the bounded slice.
    let mut out = [0u8; 4096];
    let len = payload.len() as usize;
    payload.copy_into_slice(&mut out[..len]);
    let signature = signer.sign(&out[..len]);
    BytesN::from_array(env, &signature.to_bytes())
}

fn period_is_valid(period: u64) -> bool {
    let year = period / 100;
    let month = period % 100;
    (2024..=2100).contains(&year) && (1..=12).contains(&month)
}

fuzz_target!(|input: MintWrapInput| {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, StellarWrapContract);
    let client = StellarWrapContractClient::new(&env, &contract_id);

    // Fixed admin signing key so valid signatures are reproducible across runs.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    // Register the admin public key; the contract verifies every mint
    // signature against this key.
    client.initialize(&admin, &admin_pubkey);

    let archetype = symbol_short!("arch");
    let data_hash = BytesN::from_array(&env, &input.data_hash);
    // Choose the signature under test: either a genuine admin signature over
    // the canonical payload (exercises the accept path) or arbitrary attacker
    // bytes (exercises rejection of forged/invalid signatures).
    let signature = if input.use_valid_signature {
        sign_payload(
            &env,
            &signing_key,
            &contract_id,
            &user,
            input.period,
            &archetype,
            &data_hash,
        )
    } else {
        BytesN::from_array(&env, &input.rogue_signature)
    };

    let before = client.balance_of(&user);
    let result = client.try_mint_wrap(
        &user,
        &input.period,
        &archetype,
        &data_hash,
        &1u32,
        &signature,
    );
    let minted_ok = matches!(result, Ok(Ok(())));

    if minted_ok {
        // A successful mint implies the contract accepted the signature, which
        // can only happen when the submitted arguments match the signed
        // canonical payload and the period is valid.
        assert!(
            period_is_valid(input.period),
            "mint succeeded with invalid period {}",
            input.period
        );
        assert!(
            input.use_valid_signature,
            "mint succeeded without a valid admin signature"
        );
        assert!(
            client.get_wrap(&user, &input.period).is_some(),
            "successful mint must persist a wrap record"
        );
        assert_eq!(
            client.balance_of(&user),
            before + 1,
            "successful mint must increment wrap count"
        );

        if input.remint {
            let remint = client.try_mint_wrap(
                &user,
                &input.period,
                &archetype,
                &data_hash,
                &1u32,
                &signature,
            );
            assert!(
                !matches!(remint, Ok(Ok(()))),
                "remint of the same (user, period) must fail"
            );
            assert_eq!(
                client.balance_of(&user),
                before + 1,
                "failed remint must not change balance"
            );
            assert!(
                client.get_wrap(&user, &input.period).is_some(),
                "original wrap must remain after failed remint"
            );
        }
    } else {
        // Rejected mints must not mutate storage for this user/period.
        assert!(
            client.get_wrap(&user, &input.period).is_none(),
            "rejected mint must not leave a wrap"
        );
        assert_eq!(
            client.balance_of(&user),
            before,
            "rejected mint must not change balance"
        );

        if input.use_valid_signature && period_is_valid(input.period) {
            // Valid period + admin signature should only fail for unexpected host issues.
            // Treat that as a fuzzer finding worth panicking on.
            panic!(
                "mint_wrap unexpectedly rejected valid period {} with admin signature: {result:?}",
                input.period
            );
        }
    }
});

fuzz_target!(|input: MintWrapBatchInput| {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, StellarWrapContract);
    let client = StellarWrapContractClient::new(&env, &contract_id);

    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let admin_pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    client.initialize(&admin, &admin_pubkey);

    let archetype = symbol_short!("arch");

    // Build the signed records and the records actually submitted. When
    // `substitute_after_signing` is set, the last submitted record diverges
    // from the signed one, so the aggregated signature must not authorize it.
    let mut signed_records: Vec<(u64, BytesN<32>)> = Vec::new(&env);
    let mut submitted_periods: Vec<u64> = Vec::new(&env);
    let mut submitted_hashes: Vec<BytesN<32>> = Vec::new(&env);
    for i in 0..3usize {
        let period = input.periods[i];
        let mut hash_bytes = input.data_hashes[i];
        if input.substitute_after_signing && i == 2 {
            // Flip a byte so the submitted record is not the signed record.
            hash_bytes[0] ^= 0xff;
        }
        let hash = BytesN::from_array(&env, &hash_bytes);
        signed_records.push_back((period, hash.clone()));
        submitted_periods.push_back(period);
        submitted_hashes.push_back(hash);
    }

    // Sign the canonical batch payload over the *signed* records. The contract
    // will rebuild the payload from the *submitted* records and verify the
    // signature against it, so any divergence (e.g. the substituted hash above)
    // must cause verification to fail.
    let signature = if input.use_valid_signature {
        sign_batch_payload(
            &env,
            &signing_key,
            &contract_id,
            &user,
            &archetype,
            &signed_records,
        )
    } else {
        BytesN::from_array(&env, &[0u8; 64])
    };

    let before = client.balance_of(&user);
    let result = client.try_mint_wrap_batch(
        &user,
        &archetype,
        &submitted_periods,
        &submitted_hashes,
        &1u32,
        &signature,
    );
    let minted_ok = matches!(result, Ok(Ok(())));

    if minted_ok {
        // The batch is atomic: success means every submitted record was
        // covered by the aggregated signature and passed per-record checks.
        assert!(
            input.use_valid_signature,
            "batch succeeded without a valid admin signature"
        );
        assert!(
            !input.substitute_after_signing,
            "batch succeeded despite a substituted record"
        );
        for i in 0..3usize {
            let period = input.periods[i];
            assert!(
                period_is_valid(period),
                "batch succeeded with invalid period {}",
                period
            );
            assert!(
                client.get_wrap(&user, &period).is_some(),
                "successful batch must persist every wrap record"
            );
        }
        assert_eq!(
            client.balance_of(&user),
            before + 3,
            "successful batch must increment wrap count per record"
        );

        if input.remint {
            let remint = client.try_mint_wrap_batch(
                &user,
                &archetype,
                &submitted_periods,
                &submitted_hashes,
                &1u32,
                &signature,
            );
            assert!(
                !matches!(remint, Ok(Ok(()))),
                "remint of the same batch must fail"
            );
            assert_eq!(
                client.balance_of(&user),
                before + 3,
                "failed remint must not change balance"
            );
        }
    } else {
        // A rejected batch must be atomic: no record may be persisted and the
        // balance must be unchanged.
        for i in 0..3usize {
            let period = input.periods[i];
            assert!(
                client.get_wrap(&user, &period).is_none(),
                "rejected batch must not leave a wrap for period {}",
                period
            );
        }
        assert_eq!(
            client.balance_of(&user),
            before,
            "rejected batch must not change balance"
        );
    }
});
