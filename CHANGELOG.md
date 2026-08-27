# Changelog

## 0.3.0

- Add strict attachment-replacement payloads containing a fresh descriptor and
  descriptor-bound supersession notice for one MLS application message.
- Bind replacement activation to the authenticated conversation, sender,
  purpose, and exact post-membership-change MLS security epoch.
- Persist the new protected bearer descriptor before enforcing supersession and
  make old-ciphertext cleanup an explicit sender-side option.
- Reject transfer-ID reuse and crypto providers that return the old capability
  during replacement.

## 0.2.0

- Add authenticated byte-range downloads that fetch only covering records,
  authenticate complete records, slice verified plaintext, and commit atomically.
- Add strict SHA-256 descriptor-bound revocation notices for authenticated E2EE
  delivery and trusted, immutable revocation-store enforcement.
- Recheck revocation policy throughout downloads and report ciphertext cleanup
  separately from durable access revocation.
- Document that revocation prevents future cooperating-client fetches but cannot
  recall a capability, ciphertext, or plaintext already copied by a recipient.

## 0.1.2

- Preserve the Web Crypto receiver when invoking default UUID factories in Bun
  and other runtimes with receiver-sensitive `crypto.randomUUID()` methods.

## 0.1.1

- Require receipt stores to reject updates, removal, and release from expired
  leases using an explicit caller timestamp.
- Add a lifecycle contract for bounded, cursor-based abandoned-receipt sweeps.

## 0.1.0

- Add protected, strict resumable-upload receipts with leased compare-and-swap
  persistence.
- Checkpoint a `sealing` state before record encryption to prevent AEAD nonce
  reuse after crashes or VM rollback.
- Recover ciphertext durably written before a lost checkpoint by authenticating
  it against the resumed source.
- Refuse unsafe recovery when encryption may have consumed a nonce without
  producing durable ciphertext; callers must restart with a fresh capability.

## 0.0.3

- Add a bounded `SecureTransferLifecycleStore` contract for repeatable expiry
  sweeps of crash-orphaned ciphertext.

## 0.0.2

- Allow authenticated descriptor cleanup after transfer expiry while retaining
  all provider, store, shape, size, and timestamp-consistency checks.

## 0.0.1

- Add provider-neutral record encryption and untrusted storage contracts.
- Add bounded streaming upload with strict declared-length enforcement and
  best-effort ciphertext cleanup.
- Add strict capability-bearing descriptor encoding and provider/store binding.
- Add authenticated download into transactional sinks so incomplete plaintext
  cannot be committed as a complete object.
