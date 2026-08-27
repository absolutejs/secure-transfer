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

Decryption proves record authenticity, not file safety. Treat filenames and
content types as untrusted, do not render active content inline by default, and
inspect decrypted files before parsing or executing them.
