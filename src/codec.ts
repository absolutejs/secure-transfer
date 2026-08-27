import { SecureTransferProtocolError } from "./errors";
import {
  SECURE_TRANSFER_CONTRACT,
  type SecureTransferDescriptor,
} from "./types";

const base64url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
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
