import {
  decodeSecureTransferUploadReceipt,
  encodeSecureTransferDescriptor,
  encodeSecureTransferUploadReceipt,
  hashSecureTransferDescriptor,
} from "./codec";
import {
  SecureTransferConfigurationError,
  SecureTransferProtocolError,
  SecureTransferRevokedError,
  SecureTransferResumeUnsafeError,
} from "./errors";
import {
  SECURE_TRANSFER_CONTRACT,
  SECURE_TRANSFER_REVOCATION_CONTRACT,
  SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT,
  type SecureTransferClient,
  type SecureTransferClientOptions,
  type SecureTransferByteRange,
  type SecureTransferDescriptor,
  type SecureTransferPolicy,
  type SecureTransferRecordContext,
  type SecureTransferUploadInput,
  type SecureTransferUploadMetadata,
  type SecureTransferUploadReceipt,
} from "./types";

const positiveInteger = (value: number): boolean =>
  Number.isSafeInteger(value) && value > 0;

const validatePolicy = (policy: SecureTransferPolicy): void => {
  if (
    !positiveInteger(policy.maximumAttachmentBytes) ||
    !positiveInteger(policy.maximumDescriptorBytes) ||
    !Number.isSafeInteger(policy.maximumFutureSkewMs) ||
    policy.maximumFutureSkewMs < 0 ||
    !positiveInteger(policy.maximumMetadataBytes) ||
    !positiveInteger(policy.maximumRecordPlaintextBytes) ||
    !positiveInteger(policy.maximumRecords) ||
    !positiveInteger(policy.maximumTtlMs)
  )
    throw new SecureTransferConfigurationError(
      "Secure transfer policy contains an invalid limit.",
    );
};

const metadataBytes = (...values: readonly (string | undefined)[]): number =>
  values.reduce(
    (total, value) =>
      total +
      (value === undefined ? 0 : new TextEncoder().encode(value).length),
    0,
  );

const requireText = (value: string, field: string): void => {
  if (value.trim().length === 0)
    throw new SecureTransferProtocolError(`${field} must not be empty.`);
};

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
};

const validRevocationReason = (value: unknown): boolean =>
  value === undefined ||
  value === "access-revoked" ||
  value === "member-removed" ||
  value === "superseded" ||
  value === "user-request";

const createContext = (
  descriptor: SecureTransferDescriptor,
  recordIndex: number,
): SecureTransferRecordContext => {
  const plaintextBytes =
    recordIndex === descriptor.recordCount - 1
      ? descriptor.plaintextBytes -
        descriptor.recordPlaintextBytes * (descriptor.recordCount - 1)
      : descriptor.recordPlaintextBytes;
  return Object.freeze({
    attachmentId: descriptor.attachmentId,
    conversationId: descriptor.conversationId,
    expiresAt: descriptor.expiresAt,
    final: recordIndex === descriptor.recordCount - 1,
    plaintextBytes,
    recordCount: descriptor.recordCount,
    recordIndex,
    senderDeviceId: descriptor.senderDeviceId,
    transferId: descriptor.transferId,
  });
};

const recordsFrom = async function* (
  body: ReadableStream<Uint8Array> | Uint8Array,
  recordBytes: number,
  expectedBytes: number,
): AsyncGenerator<Uint8Array> {
  const stream =
    body instanceof Uint8Array
      ? new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(body);
            controller.close();
          },
        })
      : body;
  const reader = stream.getReader();
  let current = new Uint8Array(recordBytes);
  let filled = 0;
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.length === 0)
        throw new SecureTransferProtocolError(
          "Upload stream produced an invalid record.",
        );
      if (total + value.length > expectedBytes)
        throw new SecureTransferProtocolError(
          "Upload stream exceeded its declared byte length.",
        );
      total += value.length;
      let offset = 0;
      while (offset < value.length) {
        const length = Math.min(recordBytes - filled, value.length - offset);
        current.set(value.subarray(offset, offset + length), filled);
        filled += length;
        offset += length;
        if (filled === recordBytes) {
          yield current;
          current = new Uint8Array(recordBytes);
          filled = 0;
        }
      }
    }
    if (total !== expectedBytes)
      throw new SecureTransferProtocolError(
        "Upload stream ended before its declared byte length.",
      );
    if (filled > 0) yield current.slice(0, filled);
  } finally {
    reader.releaseLock();
  }
};

export const createSecureTransferClient = (
  options: SecureTransferClientOptions,
): SecureTransferClient => {
  validatePolicy(options.policy);
  requireText(options.cryptoProvider.id, "crypto provider id");
  requireText(options.cryptoProvider.protocol, "crypto provider protocol");
  requireText(options.store.id, "store id");
  if (options.revocations !== undefined)
    requireText(options.revocations.id, "revocation store id");
  if (
    !positiveInteger(options.cryptoProvider.maximumRecordCiphertextBytes) ||
    !positiveInteger(options.cryptoProvider.maximumRecordPlaintextBytes) ||
    options.cryptoProvider.maximumRecordCiphertextBytes <=
      options.cryptoProvider.maximumRecordPlaintextBytes ||
    options.policy.maximumRecordPlaintextBytes >
      options.cryptoProvider.maximumRecordPlaintextBytes
  )
    throw new SecureTransferConfigurationError(
      "Transfer record limit exceeds the crypto provider limit.",
    );
  const now = options.now ?? Date.now;
  const transferIdFactory =
    options.transferIdFactory ?? (() => crypto.randomUUID());
  const resumable = options.resumable;
  if (resumable !== undefined) {
    requireText(resumable.protector.id, "receipt protector id");
    requireText(resumable.store.id, "receipt store id");
    if (
      !positiveInteger(resumable.leaseDurationMs) ||
      resumable.leaseDurationMs > options.policy.maximumTtlMs
    )
      throw new SecureTransferConfigurationError(
        "Receipt lease duration violates transfer policy.",
      );
  }
  const receiptIdFactory =
    resumable?.receiptIdFactory ?? (() => crypto.randomUUID());
  const leaseIdFactory =
    resumable?.leaseIdFactory ?? (() => crypto.randomUUID());
  const maximumReceiptBytes = options.policy.maximumDescriptorBytes * 2 + 1_024;
  const nextLeaseExpiry = (): number => {
    if (resumable === undefined)
      throw new SecureTransferConfigurationError(
        "Resumable uploads are not configured.",
      );
    const expiresAt = now() + resumable.leaseDurationMs;
    if (!Number.isSafeInteger(expiresAt) || expiresAt < 1)
      throw new SecureTransferProtocolError(
        "Receipt lease expiry is outside the safe timestamp range.",
      );
    return expiresAt;
  };

  const validateDescriptor = (
    descriptor: SecureTransferDescriptor,
    allowExpired = false,
  ): void => {
    requireText(descriptor.attachmentId, "attachmentId");
    requireText(descriptor.conversationId, "conversationId");
    requireText(descriptor.senderDeviceId, "senderDeviceId");
    requireText(descriptor.transferId, "transferId");
    if (
      descriptor.contract !== SECURE_TRANSFER_CONTRACT ||
      descriptor.storeId !== options.store.id ||
      descriptor.capability.providerId !== options.cryptoProvider.id ||
      descriptor.capability.protocol !== options.cryptoProvider.protocol ||
      descriptor.capability.bytes.length === 0 ||
      !positiveInteger(descriptor.plaintextBytes) ||
      descriptor.plaintextBytes > options.policy.maximumAttachmentBytes ||
      !positiveInteger(descriptor.recordPlaintextBytes) ||
      descriptor.recordPlaintextBytes >
        options.policy.maximumRecordPlaintextBytes ||
      !positiveInteger(descriptor.recordCount) ||
      descriptor.recordCount > options.policy.maximumRecords ||
      descriptor.recordCount !==
        Math.ceil(
          descriptor.plaintextBytes / descriptor.recordPlaintextBytes,
        ) ||
      !Number.isSafeInteger(descriptor.createdAt) ||
      !Number.isSafeInteger(descriptor.expiresAt) ||
      descriptor.expiresAt <= descriptor.createdAt ||
      (!allowExpired && descriptor.expiresAt <= now()) ||
      descriptor.expiresAt - descriptor.createdAt >
        options.policy.maximumTtlMs ||
      descriptor.createdAt - now() > options.policy.maximumFutureSkewMs ||
      metadataBytes(
        descriptor.attachmentId,
        descriptor.contentType,
        descriptor.conversationId,
        descriptor.fileName,
        descriptor.senderDeviceId,
        descriptor.storeId,
        descriptor.transferId,
      ) > options.policy.maximumMetadataBytes ||
      encodeSecureTransferDescriptor(descriptor).length >
        options.policy.maximumDescriptorBytes
    )
      throw new SecureTransferProtocolError(
        "Transfer descriptor violates local policy or provider binding.",
      );
  };

  const requireRevocations = () => {
    if (options.revocations === undefined)
      throw new SecureTransferConfigurationError(
        "Attachment revocation requires a trusted revocation store.",
      );
    return options.revocations;
  };

  const descriptorHash = (descriptor: SecureTransferDescriptor) =>
    hashSecureTransferDescriptor(descriptor);

  const requireNotRevoked = async (
    descriptor: SecureTransferDescriptor,
    hash: Uint8Array,
  ): Promise<void> => {
    if (
      options.revocations !== undefined &&
      (await options.revocations.has({
        descriptorHash: hash,
        transferId: descriptor.transferId,
      }))
    )
      throw new SecureTransferRevokedError(
        "Transfer access was revoked by trusted policy state.",
      );
  };

  const validateRange = (
    descriptor: SecureTransferDescriptor,
    range: SecureTransferByteRange,
  ): void => {
    if (
      !Number.isSafeInteger(range.start) ||
      range.start < 0 ||
      !Number.isSafeInteger(range.endExclusive) ||
      range.endExclusive <= range.start ||
      range.endExclusive > descriptor.plaintextBytes
    )
      throw new SecureTransferProtocolError(
        "Transfer byte range must be non-empty and within the plaintext.",
      );
  };

  const openRecord = async (
    descriptor: SecureTransferDescriptor,
    recordIndex: number,
  ): Promise<Uint8Array> => {
    const ciphertext = await options.store.getRecord({
      recordIndex,
      transferId: descriptor.transferId,
    });
    if (ciphertext === undefined)
      throw new SecureTransferProtocolError(
        `Encrypted transfer record ${recordIndex} is missing.`,
      );
    if (
      ciphertext.length === 0 ||
      ciphertext.length > options.cryptoProvider.maximumRecordCiphertextBytes
    )
      throw new SecureTransferProtocolError(
        `Encrypted transfer record ${recordIndex} violates the ciphertext limit.`,
      );
    const context = createContext(descriptor, recordIndex);
    const plaintext = await options.cryptoProvider.openRecord({
      capability: descriptor.capability,
      ciphertext,
      context,
    });
    if (plaintext.length !== context.plaintextBytes)
      throw new SecureTransferProtocolError(
        `Decrypted transfer record ${recordIndex} has the wrong size.`,
      );
    return plaintext;
  };

  const prepareUpload = async (input: SecureTransferUploadMetadata) => {
    const currentTime = now();
    requireText(input.attachmentId, "attachmentId");
    requireText(input.conversationId, "conversationId");
    requireText(input.senderDeviceId, "senderDeviceId");
    const recordPlaintextBytes =
      input.recordPlaintextBytes ?? options.policy.maximumRecordPlaintextBytes;
    if (
      !positiveInteger(input.byteLength) ||
      input.byteLength > options.policy.maximumAttachmentBytes ||
      !positiveInteger(recordPlaintextBytes) ||
      recordPlaintextBytes > options.policy.maximumRecordPlaintextBytes ||
      !Number.isSafeInteger(input.expiresAt) ||
      input.expiresAt <= currentTime ||
      input.expiresAt - currentTime > options.policy.maximumTtlMs ||
      metadataBytes(
        input.attachmentId,
        input.contentType,
        input.conversationId,
        input.fileName,
        input.senderDeviceId,
      ) > options.policy.maximumMetadataBytes
    )
      throw new SecureTransferProtocolError(
        "Upload size, metadata, record size, or expiry violates policy.",
      );
    const recordCount = Math.ceil(input.byteLength / recordPlaintextBytes);
    if (recordCount > options.policy.maximumRecords)
      throw new SecureTransferProtocolError(
        "Upload requires more records than policy permits.",
      );
    const transferId = transferIdFactory();
    requireText(transferId, "generated transferId");
    const capability = await options.cryptoProvider.createCapability();
    if (
      capability.providerId !== options.cryptoProvider.id ||
      capability.protocol !== options.cryptoProvider.protocol ||
      capability.bytes.length === 0
    )
      throw new SecureTransferProtocolError(
        "Crypto provider returned an invalid capability.",
      );
    const descriptor: SecureTransferDescriptor = Object.freeze({
      attachmentId: input.attachmentId,
      capability: Object.freeze({
        ...capability,
        bytes: capability.bytes.slice(),
      }),
      ...(input.contentType === undefined
        ? {}
        : { contentType: input.contentType }),
      contract: SECURE_TRANSFER_CONTRACT,
      conversationId: input.conversationId,
      createdAt: currentTime,
      expiresAt: input.expiresAt,
      ...(input.fileName === undefined ? {} : { fileName: input.fileName }),
      plaintextBytes: input.byteLength,
      recordCount,
      recordPlaintextBytes,
      senderDeviceId: input.senderDeviceId,
      storeId: options.store.id,
      transferId,
    });
    validateDescriptor(descriptor);
    return { capability, descriptor };
  };

  const upload = async (
    input: SecureTransferUploadInput,
  ): Promise<SecureTransferDescriptor> => {
    const { capability, descriptor } = await prepareUpload(input);
    const { recordCount, recordPlaintextBytes, transferId } = descriptor;
    let recordIndex = 0;
    let collision = false;
    try {
      for await (const plaintext of recordsFrom(
        input.body,
        recordPlaintextBytes,
        input.byteLength,
      )) {
        const ciphertext = await options.cryptoProvider.sealRecord({
          capability: descriptor.capability,
          context: createContext(descriptor, recordIndex),
          plaintext,
        });
        if (
          ciphertext.length === 0 ||
          ciphertext.length >
            options.cryptoProvider.maximumRecordCiphertextBytes
        )
          throw new SecureTransferProtocolError(
            "Crypto provider returned an empty record.",
          );
        const stored = await options.store.putRecord({
          bytes: ciphertext,
          expiresAt: input.expiresAt,
          recordIndex,
          transferId,
        });
        if (stored !== "created") {
          collision = true;
          throw new SecureTransferProtocolError(
            "Transfer storage identifier collided; no existing record was overwritten.",
          );
        }
        recordIndex += 1;
      }
      if (recordIndex !== recordCount)
        throw new SecureTransferProtocolError(
          "Upload did not produce its declared record count.",
        );
      capability.bytes.fill(0);
      return descriptor;
    } catch (error) {
      capability.bytes.fill(0);
      if (!collision)
        await options.store.removeTransfer(transferId).catch(() => undefined);
      throw error;
    }
  };

  const requireResumable = () => {
    if (resumable === undefined)
      throw new SecureTransferConfigurationError(
        "Resumable uploads require a protected receipt store and protector.",
      );
    return resumable;
  };

  const protectReceipt = async (
    receiptId: string,
    receipt: SecureTransferUploadReceipt,
  ): Promise<Uint8Array> => {
    const configured = requireResumable();
    const plaintext = encodeSecureTransferUploadReceipt(receipt);
    try {
      if (plaintext.length > maximumReceiptBytes)
        throw new SecureTransferProtocolError(
          "Upload receipt exceeds the local size limit.",
        );
      const protectedBytes = await configured.protector.protect({
        plaintext,
        receiptId,
      });
      if (
        protectedBytes.length === 0 ||
        protectedBytes.length > maximumReceiptBytes * 2
      )
        throw new SecureTransferProtocolError(
          "Receipt protector returned an invalid protected value.",
        );
      return protectedBytes;
    } finally {
      plaintext.fill(0);
    }
  };

  const openReceipt = async (
    receiptId: string,
    protectedBytes: Uint8Array,
  ): Promise<SecureTransferUploadReceipt> => {
    const configured = requireResumable();
    if (
      protectedBytes.length === 0 ||
      protectedBytes.length > maximumReceiptBytes * 2
    )
      throw new SecureTransferProtocolError(
        "Protected upload receipt violates the local size limit.",
      );
    const plaintext = await configured.protector.open({
      protectedBytes,
      receiptId,
    });
    try {
      const receipt = decodeSecureTransferUploadReceipt(
        plaintext,
        maximumReceiptBytes,
        options.policy.maximumDescriptorBytes,
      );
      validateDescriptor(receipt.descriptor);
      return receipt;
    } finally {
      plaintext.fill(0);
    }
  };

  const beginResumableUpload = async (input: SecureTransferUploadMetadata) => {
    const configured = requireResumable();
    const { capability, descriptor } = await prepareUpload(input);
    const receiptId = receiptIdFactory();
    try {
      requireText(receiptId, "generated receiptId");
      if (new TextEncoder().encode(receiptId).length > 512)
        throw new SecureTransferProtocolError(
          "Generated receiptId exceeds 512 UTF-8 bytes.",
        );
      const protectedBytes = await protectReceipt(receiptId, {
        contract: SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT,
        descriptor,
        nextRecordIndex: 0,
        phase: "ready",
      });
      try {
        const result = await configured.store.create({
          expiresAt: descriptor.expiresAt,
          protectedBytes,
          receiptId,
        });
        if (result !== "created")
          throw new SecureTransferProtocolError(
            "Generated upload receipt identifier collided.",
          );
      } finally {
        protectedBytes.fill(0);
      }
      return Object.freeze({ receiptId });
    } finally {
      capability.bytes.fill(0);
      descriptor.capability.bytes.fill(0);
    }
  };

  const resumeUpload: SecureTransferClient["resumeUpload"] = async (input) => {
    const configured = requireResumable();
    requireText(input.receiptId, "receiptId");
    const leaseId = leaseIdFactory();
    requireText(leaseId, "generated leaseId");
    const acquired = await configured.store.acquire({
      leaseExpiresAt: nextLeaseExpiry(),
      leaseId,
      now: now(),
      receiptId: input.receiptId,
    });
    if (acquired.status !== "acquired") {
      if (acquired.status === "busy")
        throw new SecureTransferProtocolError(
          "Upload receipt is already leased by another resumer.",
        );
      throw new SecureTransferProtocolError("Upload receipt does not exist.");
    }

    let version = acquired.version;
    let receipt: SecureTransferUploadReceipt | undefined;
    let completed = false;
    const checkpoint = async (
      nextReceipt: SecureTransferUploadReceipt,
    ): Promise<void> => {
      const protectedBytes = await protectReceipt(input.receiptId, nextReceipt);
      try {
        const updated = await configured.store.update({
          expiresAt: nextReceipt.descriptor.expiresAt,
          leaseExpiresAt: nextLeaseExpiry(),
          leaseId,
          now: now(),
          protectedBytes,
          receiptId: input.receiptId,
          version,
        });
        if (updated.status !== "updated")
          throw new SecureTransferProtocolError(
            "Upload receipt lease or version changed during checkpoint.",
          );
        version = updated.version;
        receipt = nextReceipt;
      } finally {
        protectedBytes.fill(0);
      }
    };

    try {
      receipt = await openReceipt(input.receiptId, acquired.protectedBytes);
      const descriptor = receipt.descriptor;
      const initialRecordIndex = receipt.nextRecordIndex;
      const byteOffset = initialRecordIndex * descriptor.recordPlaintextBytes;
      const remainingBytes = descriptor.plaintextBytes - byteOffset;
      const body = await input.source(byteOffset, remainingBytes);
      let recordIndex = initialRecordIndex;

      for await (const plaintext of recordsFrom(
        body,
        descriptor.recordPlaintextBytes,
        remainingBytes,
      )) {
        const context = createContext(descriptor, recordIndex);
        if (receipt.phase === "sealing") {
          const existing = await options.store.getRecord({
            recordIndex,
            transferId: descriptor.transferId,
          });
          if (existing === undefined)
            throw new SecureTransferResumeUnsafeError(
              "Encryption may have consumed this record nonce without durable ciphertext; restart with a fresh transfer capability.",
            );
          if (
            existing.length === 0 ||
            existing.length >
              options.cryptoProvider.maximumRecordCiphertextBytes
          )
            throw new SecureTransferProtocolError(
              "Recovered ciphertext violates the provider limit.",
            );
          const recovered = await options.cryptoProvider.openRecord({
            capability: descriptor.capability,
            ciphertext: existing,
            context,
          });
          if (!equalBytes(recovered, plaintext))
            throw new SecureTransferProtocolError(
              "Recovered ciphertext does not match the resumed source.",
            );
          recovered.fill(0);
        } else {
          const existing = await options.store.getRecord({
            recordIndex,
            transferId: descriptor.transferId,
          });
          if (existing !== undefined)
            throw new SecureTransferProtocolError(
              "Unexpected ciphertext collision before record encryption.",
            );
          await checkpoint(
            Object.freeze({
              ...receipt,
              phase: "sealing",
            }),
          );
          const ciphertext = await options.cryptoProvider.sealRecord({
            capability: descriptor.capability,
            context,
            plaintext,
          });
          if (
            ciphertext.length === 0 ||
            ciphertext.length >
              options.cryptoProvider.maximumRecordCiphertextBytes
          )
            throw new SecureTransferProtocolError(
              "Crypto provider returned an invalid record.",
            );
          const stored = await options.store.putRecord({
            bytes: ciphertext,
            expiresAt: descriptor.expiresAt,
            recordIndex,
            transferId: descriptor.transferId,
          });
          if (stored !== "created")
            throw new SecureTransferProtocolError(
              "Ciphertext appeared while a resumable record lease was held.",
            );
        }

        recordIndex += 1;
        if (recordIndex === descriptor.recordCount) {
          const removed = await configured.store.remove({
            leaseId,
            now: now(),
            receiptId: input.receiptId,
            version,
          });
          if (removed !== "removed")
            throw new SecureTransferProtocolError(
              "Upload receipt changed before completion.",
            );
          completed = true;
        } else {
          await checkpoint(
            Object.freeze({
              contract: SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT,
              descriptor,
              nextRecordIndex: recordIndex,
              phase: "ready",
            }),
          );
        }
      }
      if (recordIndex !== descriptor.recordCount || !completed)
        throw new SecureTransferProtocolError(
          "Resumed upload did not produce its remaining declared records.",
        );
      return descriptor;
    } catch (error) {
      if (receipt !== undefined) receipt.descriptor.capability.bytes.fill(0);
      throw error;
    } finally {
      acquired.protectedBytes.fill(0);
      if (!completed)
        await configured.store
          .release({
            leaseId,
            now: now(),
            receiptId: input.receiptId,
            version,
          })
          .catch(() => undefined);
    }
  };

  return Object.freeze({
    applyRevocation: async ({ descriptor, revocation }) => {
      validateDescriptor(descriptor, true);
      requireText(revocation.revokerDeviceId, "revokerDeviceId");
      if (
        revocation.contract !== SECURE_TRANSFER_REVOCATION_CONTRACT ||
        revocation.descriptorHash.length !== 32 ||
        revocation.transferId !== descriptor.transferId ||
        !Number.isSafeInteger(revocation.revokedAt) ||
        revocation.revokedAt < descriptor.createdAt ||
        revocation.revokedAt - now() > options.policy.maximumFutureSkewMs ||
        !validRevocationReason(revocation.reason)
      )
        throw new SecureTransferProtocolError(
          "Transfer revocation does not match the descriptor or local policy.",
        );
      const hash = await descriptorHash(descriptor);
      if (!equalBytes(hash, revocation.descriptorHash))
        throw new SecureTransferProtocolError(
          "Transfer revocation descriptor hash does not match.",
        );
      return requireRevocations().put({
        descriptorHash: hash.slice(),
        retainUntil: Math.max(descriptor.expiresAt, revocation.revokedAt),
        revokedAt: revocation.revokedAt,
        transferId: descriptor.transferId,
      });
    },
    beginResumableUpload,
    download: async (descriptor, sink) => {
      try {
        validateDescriptor(descriptor);
        const hash = await descriptorHash(descriptor);
        await requireNotRevoked(descriptor, hash);
        for (
          let recordIndex = 0;
          recordIndex < descriptor.recordCount;
          recordIndex += 1
        ) {
          await requireNotRevoked(descriptor, hash);
          const plaintext = await openRecord(descriptor, recordIndex);
          await sink.write(plaintext, recordIndex);
        }
        await requireNotRevoked(descriptor, hash);
        await sink.commit(descriptor);
      } catch (error) {
        await sink.abort(error).catch(() => undefined);
        throw error;
      }
    },
    downloadRange: async (descriptor, range, sink) => {
      try {
        validateDescriptor(descriptor);
        validateRange(descriptor, range);
        const hash = await descriptorHash(descriptor);
        await requireNotRevoked(descriptor, hash);
        const firstRecord = Math.floor(
          range.start / descriptor.recordPlaintextBytes,
        );
        const finalRecord = Math.floor(
          (range.endExclusive - 1) / descriptor.recordPlaintextBytes,
        );
        for (
          let recordIndex = firstRecord;
          recordIndex <= finalRecord;
          recordIndex += 1
        ) {
          await requireNotRevoked(descriptor, hash);
          const plaintext = await openRecord(descriptor, recordIndex);
          const recordOffset = recordIndex * descriptor.recordPlaintextBytes;
          const start = Math.max(0, range.start - recordOffset);
          const end = Math.min(
            plaintext.length,
            range.endExclusive - recordOffset,
          );
          await sink.write(
            plaintext.slice(start, end),
            recordIndex,
            recordOffset + start,
          );
        }
        await requireNotRevoked(descriptor, hash);
        await sink.commit(descriptor, range);
      } catch (error) {
        await sink.abort(error).catch(() => undefined);
        throw error;
      }
    },
    remove: async (descriptor) => {
      validateDescriptor(descriptor, true);
      await options.store.removeTransfer(descriptor.transferId);
    },
    revoke: async ({ descriptor, reason, revokerDeviceId }) => {
      validateDescriptor(descriptor, true);
      requireText(revokerDeviceId, "revokerDeviceId");
      if (
        new TextEncoder().encode(revokerDeviceId).length > 512 ||
        !validRevocationReason(reason)
      )
        throw new SecureTransferProtocolError(
          "Revocation device identifier or reason is invalid.",
        );
      const revokedAt = now();
      if (!Number.isSafeInteger(revokedAt) || revokedAt < descriptor.createdAt)
        throw new SecureTransferProtocolError(
          "Revocation timestamp precedes the transfer or is unsafe.",
        );
      const hash = await descriptorHash(descriptor);
      await requireRevocations().put({
        descriptorHash: hash.slice(),
        retainUntil: Math.max(descriptor.expiresAt, revokedAt),
        revokedAt,
        transferId: descriptor.transferId,
      });
      let ciphertextRemoved = true;
      try {
        await options.store.removeTransfer(descriptor.transferId);
      } catch {
        ciphertextRemoved = false;
      }
      return Object.freeze({
        ciphertextRemoved,
        revocation: Object.freeze({
          contract: SECURE_TRANSFER_REVOCATION_CONTRACT,
          descriptorHash: hash.slice(),
          ...(reason === undefined ? {} : { reason }),
          revokedAt,
          revokerDeviceId,
          transferId: descriptor.transferId,
        }),
      });
    },
    resumeUpload,
    upload,
  });
};
