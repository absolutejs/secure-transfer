# Changelog

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
