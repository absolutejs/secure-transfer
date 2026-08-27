# Security policy

This package is experimental and has not received an independent security audit.
Do not describe it as audited or production-approved.

Report vulnerabilities privately through GitHub Security Advisories for
`absolutejs/secure-transfer`. Do not attach plaintext, decryption capabilities,
private keys, or live ciphertext.

The descriptor is a bearer decryption capability and must itself travel through
an authenticated E2EE channel. Transactional sinks must stage writes and make
them visible only from `commit()`. Storage implementations must use create-only
record writes, enforce expiry, and prevent transfer IDs from becoming paths.

Resumable receipts contain the same bearer capability and must be protected with
authenticated encryption before persistence. Use a distinct receipt-protection
key, keep it outside object storage, and require atomic leases plus
compare-and-swap updates in the receipt store.

Revocation tombstones are trusted policy state, not cryptographic recall. Keep
them separate from the untrusted ciphertext store, create them immutably, retain
them through descriptor expiry, and fail closed if policy state is unavailable.
Only apply a received notice after the E2EE sender identity and revocation
authority have been verified. Deleting ciphertext or key material cannot erase
copies already held by a recipient.

Decryption proves record authenticity, not file safety. Treat filenames and
content types as untrusted, do not render active content inline by default, and
inspect decrypted files before parsing or executing them.
