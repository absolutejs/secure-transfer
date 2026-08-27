export const SECURE_TRANSFER_CONTRACT = 1 as const;
export const SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT = 1 as const;

export type SecureTransferRecordContext = {
  readonly attachmentId: string;
  readonly conversationId: string;
  readonly expiresAt: number;
  readonly final: boolean;
  readonly plaintextBytes: number;
  readonly recordCount: number;
  readonly recordIndex: number;
  readonly senderDeviceId: string;
  readonly transferId: string;
};

export type SecureTransferCapability = {
  readonly bytes: Uint8Array;
  readonly protocol: string;
  readonly providerId: string;
};

export type SecureTransferCryptoProvider = {
  readonly id: string;
  readonly maximumRecordCiphertextBytes: number;
  readonly maximumRecordPlaintextBytes: number;
  readonly protocol: string;
  createCapability(): Promise<SecureTransferCapability>;
  openRecord(input: {
    readonly capability: SecureTransferCapability;
    readonly ciphertext: Uint8Array;
    readonly context: SecureTransferRecordContext;
  }): Promise<Uint8Array>;
  sealRecord(input: {
    readonly capability: SecureTransferCapability;
    readonly context: SecureTransferRecordContext;
    readonly plaintext: Uint8Array;
  }): Promise<Uint8Array>;
};

export type SecureTransferStore = {
  readonly id: string;
  getRecord(input: {
    readonly recordIndex: number;
    readonly transferId: string;
  }): Promise<Uint8Array | undefined>;
  putRecord(input: {
    readonly bytes: Uint8Array;
    readonly expiresAt: number;
    readonly recordIndex: number;
    readonly transferId: string;
  }): Promise<"created" | "exists">;
  removeTransfer(transferId: string): Promise<void>;
};

export type SecureTransferExpirySweepInput = {
  /** Opaque continuation returned by the previous bounded sweep. */
  readonly cursor?: string;
  /** Delete records whose storage expiry is at or before this time. */
  readonly expiresAtOrBefore: number;
  /** Bound provider work performed by one repeatable sweep. */
  readonly maximumRecords: number;
};

export type SecureTransferExpirySweepResult = {
  /** Pass this to the next sweep when `truncated` is true. */
  readonly cursor?: string;
  readonly examinedRecords: number;
  readonly removedRecords: number;
  /** Continue sweeping until this is false. */
  readonly truncated: boolean;
};

/** Optional lifecycle capability implemented by production storage adapters. */
export type SecureTransferLifecycleStore = SecureTransferStore & {
  sweepExpired(
    input: SecureTransferExpirySweepInput,
  ): Promise<SecureTransferExpirySweepResult>;
};

export type SecureTransferDescriptor = {
  readonly attachmentId: string;
  readonly capability: SecureTransferCapability;
  readonly contentType?: string;
  readonly contract: typeof SECURE_TRANSFER_CONTRACT;
  readonly conversationId: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly fileName?: string;
  readonly plaintextBytes: number;
  readonly recordCount: number;
  readonly recordPlaintextBytes: number;
  readonly senderDeviceId: string;
  readonly storeId: string;
  readonly transferId: string;
};

export type SecureTransferPolicy = {
  readonly maximumAttachmentBytes: number;
  readonly maximumDescriptorBytes: number;
  readonly maximumFutureSkewMs: number;
  readonly maximumMetadataBytes: number;
  readonly maximumRecordPlaintextBytes: number;
  readonly maximumRecords: number;
  readonly maximumTtlMs: number;
};

export type SecureTransferClientOptions = {
  readonly cryptoProvider: SecureTransferCryptoProvider;
  readonly now?: () => number;
  readonly policy: SecureTransferPolicy;
  readonly store: SecureTransferStore;
  readonly transferIdFactory?: () => string;
  readonly resumable?: SecureTransferResumableOptions;
};

export type SecureTransferUploadInput = {
  readonly attachmentId: string;
  readonly body: ReadableStream<Uint8Array> | Uint8Array;
  readonly byteLength: number;
  readonly contentType?: string;
  readonly conversationId: string;
  readonly expiresAt: number;
  readonly fileName?: string;
  readonly recordPlaintextBytes?: number;
  readonly senderDeviceId: string;
};

export type SecureTransferUploadMetadata = Omit<
  SecureTransferUploadInput,
  "body"
>;

export type SecureTransferUploadReceipt = {
  readonly contract: typeof SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT;
  readonly descriptor: SecureTransferDescriptor;
  readonly nextRecordIndex: number;
  /** `sealing` means encryption began but durable record creation is unconfirmed. */
  readonly phase: "ready" | "sealing";
};

export type SecureTransferReceiptProtector = {
  readonly id: string;
  open(input: {
    readonly protectedBytes: Uint8Array;
    readonly receiptId: string;
  }): Promise<Uint8Array>;
  protect(input: {
    readonly plaintext: Uint8Array;
    readonly receiptId: string;
  }): Promise<Uint8Array>;
};

export type SecureTransferProtectedReceiptStore = {
  readonly id: string;
  acquire(input: {
    readonly leaseExpiresAt: number;
    readonly leaseId: string;
    readonly now: number;
    readonly receiptId: string;
  }): Promise<
    | {
        readonly protectedBytes: Uint8Array;
        readonly status: "acquired";
        readonly version: string;
      }
    | { readonly status: "busy" | "missing" }
  >;
  create(input: {
    readonly expiresAt: number;
    readonly protectedBytes: Uint8Array;
    readonly receiptId: string;
  }): Promise<"created" | "exists">;
  release(input: {
    readonly leaseId: string;
    readonly receiptId: string;
    readonly version: string;
  }): Promise<void>;
  remove(input: {
    readonly leaseId: string;
    readonly receiptId: string;
    readonly version: string;
  }): Promise<"removed" | "conflict">;
  update(input: {
    readonly expiresAt: number;
    readonly leaseExpiresAt: number;
    readonly leaseId: string;
    readonly protectedBytes: Uint8Array;
    readonly receiptId: string;
    readonly version: string;
  }): Promise<
    | { readonly status: "conflict" }
    | { readonly status: "updated"; readonly version: string }
  >;
};

export type SecureTransferResumableOptions = {
  readonly leaseDurationMs: number;
  readonly leaseIdFactory?: () => string;
  readonly protector: SecureTransferReceiptProtector;
  readonly receiptIdFactory?: () => string;
  readonly store: SecureTransferProtectedReceiptStore;
};

export type SecureTransferResumeSource = (
  byteOffset: number,
  remainingBytes: number,
) =>
  | Promise<ReadableStream<Uint8Array> | Uint8Array>
  | ReadableStream<Uint8Array>
  | Uint8Array;

export type SecureTransferSink = {
  readonly abort: (reason: unknown) => Promise<void>;
  readonly commit: (descriptor: SecureTransferDescriptor) => Promise<void>;
  readonly write: (record: Uint8Array, recordIndex: number) => Promise<void>;
};

export type SecureTransferClient = {
  readonly beginResumableUpload: (
    input: SecureTransferUploadMetadata,
  ) => Promise<{ readonly receiptId: string }>;
  readonly download: (
    descriptor: SecureTransferDescriptor,
    sink: SecureTransferSink,
  ) => Promise<void>;
  readonly remove: (descriptor: SecureTransferDescriptor) => Promise<void>;
  readonly resumeUpload: (input: {
    readonly receiptId: string;
    readonly source: SecureTransferResumeSource;
  }) => Promise<SecureTransferDescriptor>;
  readonly upload: (
    input: SecureTransferUploadInput,
  ) => Promise<SecureTransferDescriptor>;
};
