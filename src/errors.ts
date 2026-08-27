export class SecureTransferError extends Error {
  override readonly name: string = "SecureTransferError";
}

export class SecureTransferConfigurationError extends SecureTransferError {
  override readonly name = "SecureTransferConfigurationError";
}

export class SecureTransferProtocolError extends SecureTransferError {
  override readonly name = "SecureTransferProtocolError";
}

/** The transfer must restart with a fresh capability to preserve nonce uniqueness. */
export class SecureTransferResumeUnsafeError extends SecureTransferError {
  override readonly name = "SecureTransferResumeUnsafeError";
}

/** A trusted policy tombstone forbids this client from fetching the transfer. */
export class SecureTransferRevokedError extends SecureTransferError {
  override readonly name = "SecureTransferRevokedError";
}
