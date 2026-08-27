import { SecureTransferProtocolError } from "./errors";
import {
  SECURE_TRANSFER_CONTRACT,
  SECURE_TRANSFER_REVOCATION_CONTRACT,
  SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT,
  type SecureTransferDescriptor,
  type SecureTransferRevocation,
  type SecureTransferUploadReceipt,
} from "./types";

const base64url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
};

export const hashSecureTransferDescriptor = async (
  descriptor: SecureTransferDescriptor,
): Promise<Uint8Array> => {
  const encoded = encodeSecureTransferDescriptor(descriptor);
  const bytes = encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  ) as ArrayBuffer;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
};

export const encodeSecureTransferRevocation = (
  revocation: SecureTransferRevocation,
): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify({
      contract: revocation.contract,
      descriptorHash: base64url(revocation.descriptorHash),
      ...(revocation.reason === undefined ? {} : { reason: revocation.reason }),
      revokedAt: revocation.revokedAt,
      revokerDeviceId: revocation.revokerDeviceId,
      transferId: revocation.transferId,
    }),
  );

export const decodeSecureTransferRevocation = (
  bytes: Uint8Array,
  maximumBytes: number,
): SecureTransferRevocation => {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    bytes.length === 0 ||
    bytes.length > maximumBytes
  )
    throw new SecureTransferProtocolError(
      "Transfer revocation violates the encoded size limit.",
    );
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new SecureTransferProtocolError(
      "Transfer revocation is not valid JSON.",
    );
  }
  const reasons = new Set([
    "access-revoked",
    "member-removed",
    "superseded",
    "user-request",
  ]);
  if (
    !isRecord(value) ||
    !exactKeys(
      value,
      [
        "contract",
        "descriptorHash",
        "revokedAt",
        "revokerDeviceId",
        "transferId",
      ],
      ["reason"],
    ) ||
    value.contract !== SECURE_TRANSFER_REVOCATION_CONTRACT ||
    typeof value.descriptorHash !== "string" ||
    !isPositiveInteger(value.revokedAt) ||
    !isText(value.revokerDeviceId) ||
    !isText(value.transferId) ||
    (value.reason !== undefined &&
      (typeof value.reason !== "string" || !reasons.has(value.reason)))
  )
    throw new SecureTransferProtocolError(
      "Transfer revocation shape is invalid or contains unknown fields.",
    );
  const descriptorHash = fromBase64url(value.descriptorHash);
  if (descriptorHash.length !== 32)
    throw new SecureTransferProtocolError(
      "Transfer revocation descriptor hash must be SHA-256.",
    );
  return Object.freeze({
    contract: SECURE_TRANSFER_REVOCATION_CONTRACT,
    descriptorHash,
    ...(value.reason === undefined ? {} : { reason: value.reason }),
    revokedAt: value.revokedAt,
    revokerDeviceId: value.revokerDeviceId,
    transferId: value.transferId,
  }) as SecureTransferRevocation;
};

const fromBase64url = (value: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]+$/u.test(value))
    throw new SecureTransferProtocolError(
      "Transfer capability is not canonical base64url.",
    );
  const standard = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new SecureTransferProtocolError(
      "Transfer capability is not valid base64url.",
    );
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64url(bytes) !== value)
    throw new SecureTransferProtocolError(
      "Transfer capability is not canonical base64url.",
    );
  return bytes;
};

const exactKeys = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean => {
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
  );
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;

const isPositiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && Number(value) > 0;

export const encodeSecureTransferDescriptor = (
  descriptor: SecureTransferDescriptor,
): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify({
      attachmentId: descriptor.attachmentId,
      capability: {
        bytes: base64url(descriptor.capability.bytes),
        protocol: descriptor.capability.protocol,
        providerId: descriptor.capability.providerId,
      },
      ...(descriptor.contentType === undefined
        ? {}
        : { contentType: descriptor.contentType }),
      contract: descriptor.contract,
      conversationId: descriptor.conversationId,
      createdAt: descriptor.createdAt,
      expiresAt: descriptor.expiresAt,
      ...(descriptor.fileName === undefined
        ? {}
        : { fileName: descriptor.fileName }),
      plaintextBytes: descriptor.plaintextBytes,
      recordCount: descriptor.recordCount,
      recordPlaintextBytes: descriptor.recordPlaintextBytes,
      senderDeviceId: descriptor.senderDeviceId,
      storeId: descriptor.storeId,
      transferId: descriptor.transferId,
    }),
  );

export const decodeSecureTransferDescriptor = (
  bytes: Uint8Array,
  maximumBytes: number,
): SecureTransferDescriptor => {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    bytes.length === 0 ||
    bytes.length > maximumBytes
  )
    throw new SecureTransferProtocolError(
      "Transfer descriptor violates the encoded size limit.",
    );
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new SecureTransferProtocolError(
      "Transfer descriptor is not valid JSON.",
    );
  }
  const required = [
    "attachmentId",
    "capability",
    "contract",
    "conversationId",
    "createdAt",
    "expiresAt",
    "plaintextBytes",
    "recordCount",
    "recordPlaintextBytes",
    "senderDeviceId",
    "storeId",
    "transferId",
  ] as const;
  if (
    !isRecord(value) ||
    !exactKeys(value, required, ["contentType", "fileName"]) ||
    !isRecord(value.capability) ||
    !exactKeys(value.capability, ["bytes", "protocol", "providerId"]) ||
    value.contract !== SECURE_TRANSFER_CONTRACT ||
    !isText(value.attachmentId) ||
    !isText(value.conversationId) ||
    !isText(value.senderDeviceId) ||
    !isText(value.storeId) ||
    !isText(value.transferId) ||
    !isText(value.capability.protocol) ||
    !isText(value.capability.providerId) ||
    typeof value.capability.bytes !== "string" ||
    !isPositiveInteger(value.createdAt) ||
    !isPositiveInteger(value.expiresAt) ||
    !isPositiveInteger(value.plaintextBytes) ||
    !isPositiveInteger(value.recordCount) ||
    !isPositiveInteger(value.recordPlaintextBytes) ||
    (value.contentType !== undefined && !isText(value.contentType)) ||
    (value.fileName !== undefined && !isText(value.fileName))
  )
    throw new SecureTransferProtocolError(
      "Transfer descriptor shape is invalid or contains unknown fields.",
    );
  return Object.freeze({
    attachmentId: value.attachmentId,
    capability: Object.freeze({
      bytes: fromBase64url(value.capability.bytes),
      protocol: value.capability.protocol,
      providerId: value.capability.providerId,
    }),
    ...(value.contentType === undefined
      ? {}
      : { contentType: value.contentType }),
    contract: SECURE_TRANSFER_CONTRACT,
    conversationId: value.conversationId,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    ...(value.fileName === undefined ? {} : { fileName: value.fileName }),
    plaintextBytes: value.plaintextBytes,
    recordCount: value.recordCount,
    recordPlaintextBytes: value.recordPlaintextBytes,
    senderDeviceId: value.senderDeviceId,
    storeId: value.storeId,
    transferId: value.transferId,
  });
};

export const encodeSecureTransferUploadReceipt = (
  receipt: SecureTransferUploadReceipt,
): Uint8Array =>
  new TextEncoder().encode(
    JSON.stringify({
      contract: receipt.contract,
      descriptor: base64url(encodeSecureTransferDescriptor(receipt.descriptor)),
      nextRecordIndex: receipt.nextRecordIndex,
      phase: receipt.phase,
    }),
  );

export const decodeSecureTransferUploadReceipt = (
  bytes: Uint8Array,
  maximumBytes: number,
  maximumDescriptorBytes: number,
): SecureTransferUploadReceipt => {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    bytes.length === 0 ||
    bytes.length > maximumBytes
  )
    throw new SecureTransferProtocolError(
      "Upload receipt violates the encoded size limit.",
    );
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new SecureTransferProtocolError("Upload receipt is not valid JSON.");
  }
  if (
    !isRecord(value) ||
    !exactKeys(value, ["contract", "descriptor", "nextRecordIndex", "phase"]) ||
    value.contract !== SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT ||
    typeof value.descriptor !== "string" ||
    !Number.isSafeInteger(value.nextRecordIndex) ||
    Number(value.nextRecordIndex) < 0 ||
    (value.phase !== "ready" && value.phase !== "sealing")
  )
    throw new SecureTransferProtocolError(
      "Upload receipt shape is invalid or contains unknown fields.",
    );
  const descriptor = decodeSecureTransferDescriptor(
    fromBase64url(value.descriptor),
    maximumDescriptorBytes,
  );
  if (Number(value.nextRecordIndex) >= descriptor.recordCount)
    throw new SecureTransferProtocolError(
      "Upload receipt record position is outside the transfer.",
    );
  return Object.freeze({
    contract: SECURE_TRANSFER_UPLOAD_RECEIPT_CONTRACT,
    descriptor,
    nextRecordIndex: Number(value.nextRecordIndex),
    phase: value.phase,
  });
};
