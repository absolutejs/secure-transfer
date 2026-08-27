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

Version `0.1.0` provides upload, strict descriptor and receipt encoding,
authenticated download, resumable crash recovery, transactional sinks, cleanup,
and provider/store contracts. Range selection and attachment revocation remain
roadmap work. Concrete local and S3/R2 storage adapters live in
[`secure-transfer-adapters`](https://github.com/absolutejs/secure-transfer-adapters).

## License

Apache-2.0
