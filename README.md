# `@absolutejs/secure-transfer`

Provider-neutral encrypted large-object transfer for AbsoluteJS. It splits a
known-length source into bounded, independently authenticated records, writes
only ciphertext to an untrusted store, and downloads into a transactional sink.

```ts
const transfer = createSecureTransferClient({
  cryptoProvider,
  store,
  policy: {
    maximumAttachmentBytes: 1024 ** 4,
    maximumDescriptorBytes: 16 * 1024,
    maximumFutureSkewMs: 300_000,
    maximumMetadataBytes: 4 * 1024,
    maximumRecordPlaintextBytes: 1024 * 1024,
    maximumRecords: 1_048_576,
    maximumTtlMs: 7 * 24 * 60 * 60 * 1000,
  },
});

const descriptor = await transfer.upload({
  attachmentId: crypto.randomUUID(),
  body: file.stream(),
  byteLength: file.size,
  contentType: file.type,
  conversationId,
  expiresAt: Date.now() + 86_400_000,
  fileName: file.name,
  senderDeviceId,
});

await messaging.send({
  conversationId,
  id: crypto.randomUUID(),
  plaintext: encodeSecureTransferDescriptor(descriptor),
  purpose: "secure-transfer.descriptor",
  ttlMs: 86_400_000,
});
```

## Authenticated byte ranges

`downloadRange()` authenticates every complete encrypted record covering the
requested interval, then passes only the selected plaintext bytes to a
transactional range sink. The range is `[start, endExclusive)` and must be
non-empty and within the descriptor's declared plaintext size.

```ts
await transfer.downloadRange(
  descriptor,
  { start: 1_048_576, endExclusive: 2_097_152 },
  rangeSink,
);
```

This proves the authenticity and position of the requested records against the
descriptor. It intentionally does not fetch or prove the current availability
of records outside the range.

## Honest revocation

Configure a trusted `SecureTransferRevocationStore`, then create the durable
tombstone before attempting ciphertext cleanup:

```ts
const { revocation, ciphertextRemoved } = await transfer.revoke({
  descriptor,
  reason: "member-removed",
  revokerDeviceId,
});

await messaging.send({
  conversationId,
  id: crypto.randomUUID(),
  plaintext: encodeSecureTransferRevocation(revocation),
  purpose: "secure-transfer.revocation",
  ttlMs,
});
```

Recipients must authenticate the E2EE sender, authorize that device to revoke
the attachment, strictly decode the notice, and only then call
`applyRevocation()`. The notice is bound to the exact descriptor by a SHA-256
hash. Downloads consult trusted policy state before and throughout retrieval and
fail closed when that store errors. Keep tombstones at least through the
descriptor expiry; `ciphertextRemoved: false` means cleanup must be retried even
though cooperating clients already block the transfer.

Revocation is not retroactive cryptographic erasure. A bearer capability,
ciphertext, or plaintext already copied by a recipient cannot be recalled.
After an MLS member removal, use a fresh capability for replacement content and
deliver its descriptor only in the new epoch; removal protects future epoch
traffic, not secrets the former member already received. This follows the epoch
and member-removal model in [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html).
Where a deployment uses cryptographic erase for storage cleanup, follow the key
sanitization program in
[NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final); that still
does not sanitize independently held recipient copies.

## Resumable uploads

Configure a `SecureTransferReceiptProtector` and
`SecureTransferProtectedReceiptStore`, then persist the initial protected receipt
before reading the source:

```ts
const { receiptId } = await transfer.beginResumableUpload({
  attachmentId,
  byteLength: file.size,
  conversationId,
  expiresAt,
  fileName: file.name,
  senderDeviceId,
});

const descriptor = await transfer.resumeUpload({
  receiptId,
  source: (byteOffset) => file.slice(byteOffset).stream(),
});
```

Receipts contain the transfer's bearer decryption capability. Core passes only
protected opaque bytes to receipt storage and binds protection to `receiptId`.
Use an authenticated protector backed by a key that is separate from object
storage credentials. Never implement the protector as plaintext or reversible
encoding.

Receipt stores must implement atomic lease acquisition and compare-and-swap
updates. Core checkpoints `phase: "sealing"` before invoking record encryption.
If a crash occurs after ciphertext storage, resume authenticates that ciphertext
against the source before advancing. If encryption might have happened but no
ciphertext is durable, `SecureTransferResumeUnsafeError` requires a new transfer
and capability rather than risking nonce reuse.
Receipt adapters should implement
`SecureTransferProtectedReceiptLifecycleStore`; run `sweepExpiredReceipts()`
with its returned cursor until `truncated` is false.

The descriptor contains the decryption capability and sensitive metadata. It is
plaintext until the caller protects it with `@absolutejs/secure-messaging` or an
E2EE envelope. Never place it in object metadata, logs, URLs, push payloads, or a
normal chat message.

## Security model

- Storage receives opaque transfer IDs, record indexes, ciphertext sizes, and
  expiry. It does not receive filenames, media types, conversation IDs, or keys.
- Every record is bound to the transfer, attachment, conversation, sender,
  position, total count, expected plaintext size, final-record marker, and expiry.
- Record creation is create-only. A collision must never overwrite ciphertext.
- Missing, reordered, substituted, duplicated, truncated, and extended records
  fail authentication or descriptor validation.
- Downloads target a staging sink. `commit()` occurs only after every record is
  authenticated; failure calls `abort()` so partial plaintext is not mistaken for
  a complete file.
- Range downloads preserve the same staging rule but authenticate only records
  intersecting the requested byte interval.
- Revocation stores are trusted authorization state and should use credentials
  and retention controls distinct from untrusted ciphertext storage.
- Upload failure makes a best-effort ciphertext cleanup. Production adapters
  should implement `SecureTransferLifecycleStore` and run bounded expiry sweeps
  repeatedly with the returned `cursor` until `truncated` is false so live
  records at the start of a listing cannot starve crash-orphan cleanup.

This framing is inspired by [RFC 8188](https://www.rfc-editor.org/rfc/rfc8188.html),
especially its authenticated record sequence, truncation handling, and unique
per-record nonce requirements. It is not the RFC 8188 HTTP wire format.
The resumable state machine follows
[RFC 5116 section 3.1](https://www.rfc-editor.org/rfc/rfc5116.html#section-3.1),
which calls for durable nonce checkpointing before encryption proceeds.

File names and media types are untrusted display hints. Applications must enforce
allowlists, size limits, safe download dispositions, and client-side inspection
after decryption. Server-side malware scanning cannot inspect end-to-end encrypted
ciphertext without deliberately changing the confidentiality boundary.

## Scope

Version `0.2.0` provides upload, strict descriptor, receipt, and revocation
encoding, full and byte-range authenticated download, resumable crash recovery,
transactional sinks, honest future-fetch revocation, cleanup, and provider/store
contracts. Concrete local and S3/R2 storage adapters live in
[`secure-transfer-adapters`](https://github.com/absolutejs/secure-transfer-adapters).

## License

Apache-2.0
