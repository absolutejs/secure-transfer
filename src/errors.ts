export class SecureTransferError extends Error {
  override readonly name: string = "SecureTransferError";
}

export class SecureTransferConfigurationError extends SecureTransferError {
  override readonly name = "SecureTransferConfigurationError";
}

export class SecureTransferProtocolError extends SecureTransferError {
  override readonly name = "SecureTransferProtocolError";
}
