import { encodeSecureTransferDescriptor } from "./codec";
import {
  SecureTransferConfigurationError,
  SecureTransferProtocolError,
} from "./errors";
import {
  SECURE_TRANSFER_CONTRACT,
  type SecureTransferClient,
  type SecureTransferClientOptions,
  type SecureTransferDescriptor,
  type SecureTransferPolicy,
  type SecureTransferRecordContext,
  type SecureTransferUploadInput,
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
  const transferIdFactory = options.transferIdFactory ?? crypto.randomUUID;

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

  const upload = async (
    input: SecureTransferUploadInput,
  ): Promise<SecureTransferDescriptor> => {
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

  return Object.freeze({
    download: async (descriptor, sink) => {
      try {
        validateDescriptor(descriptor);
        for (
          let recordIndex = 0;
          recordIndex < descriptor.recordCount;
          recordIndex += 1
        ) {
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
            ciphertext.length >
              options.cryptoProvider.maximumRecordCiphertextBytes
          )
            throw new SecureTransferProtocolError(
              `Encrypted transfer record ${recordIndex} violates the ciphertext limit.`,
            );
          const plaintext = await options.cryptoProvider.openRecord({
            capability: descriptor.capability,
            ciphertext,
            context: createContext(descriptor, recordIndex),
          });
          const expected = createContext(
            descriptor,
            recordIndex,
          ).plaintextBytes;
          if (plaintext.length !== expected)
            throw new SecureTransferProtocolError(
              `Decrypted transfer record ${recordIndex} has the wrong size.`,
            );
          await sink.write(plaintext, recordIndex);
        }
        await sink.commit(descriptor);
      } catch (error) {
        await sink.abort(error).catch(() => undefined);
        throw error;
      }
    },
    remove: async (descriptor) => {
      validateDescriptor(descriptor, true);
      await options.store.removeTransfer(descriptor.transferId);
    },
    upload,
  });
};
