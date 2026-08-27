import { describe, expect, test } from "bun:test";
import {
  SECURE_TRANSFER_CONTRACT,
  createSecureTransferClient,
  decodeSecureTransferDescriptor,
  encodeSecureTransferDescriptor,
  type SecureTransferCryptoProvider,
  type SecureTransferSink,
  type SecureTransferStore,
} from "../src";

const createSurface = () => {
  let currentTime = 1_000;
  const records = new Map<string, Uint8Array>();
  const removed: string[] = [];
  const store: SecureTransferStore = {
    id: "memory-store",
    getRecord: async ({ recordIndex, transferId }) =>
      records.get(`${transferId}:${recordIndex}`)?.slice(),
    putRecord: async ({ bytes, recordIndex, transferId }) => {
      const key = `${transferId}:${recordIndex}`;
      if (records.has(key)) return "exists";
      records.set(key, bytes.slice());
      return "created";
    },
    removeTransfer: async (transferId) => {
      removed.push(transferId);
      for (const key of [...records.keys()])
        if (key.startsWith(`${transferId}:`)) records.delete(key);
    },
  };
  const provider: SecureTransferCryptoProvider = {
    id: "test.crypto",
    maximumRecordCiphertextBytes: 9,
    maximumRecordPlaintextBytes: 8,
    protocol: "TEST-1",
    createCapability: async () => ({
      bytes: Uint8Array.of(42),
      protocol: "TEST-1",
      providerId: "test.crypto",
    }),
    openRecord: async ({ ciphertext, context }) => {
      if (ciphertext[0] !== context.recordIndex)
        throw new Error("record context mismatch");
      return ciphertext.slice(1);
    },
    sealRecord: async ({ context, plaintext }) =>
      Uint8Array.from([context.recordIndex, ...plaintext]),
  };
  const client = createSecureTransferClient({
    cryptoProvider: provider,
    now: () => currentTime,
    policy: {
      maximumAttachmentBytes: 64,
      maximumDescriptorBytes: 2_048,
      maximumFutureSkewMs: 100,
      maximumMetadataBytes: 256,
      maximumRecordPlaintextBytes: 4,
      maximumRecords: 16,
      maximumTtlMs: 1_000,
    },
    store,
    transferIdFactory: () => "transfer-1",
  });
  return {
    client,
    records,
    removed,
    setNow: (value: number) => {
      currentTime = value;
    },
  };
};

const upload = (surface: ReturnType<typeof createSurface>) =>
  surface.client.upload({
    attachmentId: "attachment-1",
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(Uint8Array.of(1, 2, 3));
        controller.enqueue(Uint8Array.of(4, 5, 6, 7, 8, 9));
        controller.close();
      },
    }),
    byteLength: 9,
    contentType: "application/octet-stream",
    conversationId: "conversation-1",
    expiresAt: 1_500,
    fileName: "private.bin",
    senderDeviceId: "alice-phone",
  });

describe("secure transfer client", () => {
  test("uploads bounded records and commits plaintext only after full authentication", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    expect(descriptor.recordCount).toBe(3);
    expect([...surface.records.values()].map(({ length }) => length)).toEqual([
      5, 5, 2,
    ]);
    const staged: Uint8Array[] = [];
    let committed = false;
    const sink: SecureTransferSink = {
      abort: async () => {
        staged.length = 0;
      },
      commit: async () => {
        committed = true;
      },
      write: async (record) => {
        staged.push(record.slice());
      },
    };
    await surface.client.download(descriptor, sink);
    expect(committed).toBe(true);
    expect([...staged.flatMap((bytes) => [...bytes])]).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9,
    ]);
  });

  test("aborts a staged destination on missing or substituted records", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    surface.records.delete("transfer-1:1");
    let aborted = false;
    let committed = false;
    await expect(
      surface.client.download(descriptor, {
        abort: async () => {
          aborted = true;
        },
        commit: async () => {
          committed = true;
        },
        write: async () => undefined,
      }),
    ).rejects.toThrow("missing");
    expect({ aborted, committed }).toEqual({ aborted: true, committed: false });
  });

  test("cleans staged ciphertext when the source length is dishonest", async () => {
    const surface = createSurface();
    await expect(
      surface.client.upload({
        attachmentId: "attachment-1",
        body: Uint8Array.of(1, 2),
        byteLength: 3,
        conversationId: "conversation-1",
        expiresAt: 1_500,
        senderDeviceId: "alice-phone",
      }),
    ).rejects.toThrow("ended before");
    expect(surface.records.size).toBe(0);
    expect(surface.removed).toEqual(["transfer-1"]);
  });

  test("strictly round-trips descriptors and rejects extension smuggling", async () => {
    const descriptor = await upload(createSurface());
    const encoded = encodeSecureTransferDescriptor(descriptor);
    expect(decodeSecureTransferDescriptor(encoded, 2_048)).toEqual(descriptor);
    const extended = new TextEncoder().encode(
      JSON.stringify({
        ...JSON.parse(new TextDecoder().decode(encoded)),
        downloadUrl: "https://attacker.invalid",
      }),
    );
    expect(() => decodeSecureTransferDescriptor(extended, 2_048)).toThrow(
      "unknown fields",
    );
    expect(descriptor.contract).toBe(SECURE_TRANSFER_CONTRACT);
  });

  test("allows expired ciphertext cleanup but rejects expired download", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    surface.setNow(2_000);
    await expect(
      surface.client.download(descriptor, {
        abort: async () => undefined,
        commit: async () => undefined,
        write: async () => undefined,
      }),
    ).rejects.toThrow("local policy");
    await surface.client.remove(descriptor);
    expect(surface.records.size).toBe(0);
  });
});
