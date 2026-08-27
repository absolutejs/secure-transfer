import { describe, expect, test } from "bun:test";
import {
  SECURE_TRANSFER_CONTRACT,
  createSecureTransferClient,
  decodeSecureTransferDescriptor,
  decodeSecureTransferReplacement,
  decodeSecureTransferRevocation,
  decodeSecureTransferUploadReceipt,
  encodeSecureTransferDescriptor,
  encodeSecureTransferReplacement,
  encodeSecureTransferRevocation,
  encodeSecureTransferUploadReceipt,
  SecureTransferResumeUnsafeError,
  type SecureTransferCryptoProvider,
  type SecureTransferProtectedReceiptStore,
  type SecureTransferReceiptProtector,
  type SecureTransferRevocationStore,
  type SecureTransferSink,
  type SecureTransferStore,
} from "../src";

const createSurface = (useDefaultIdFactories = false) => {
  let currentTime = 1_000;
  let capabilityId = 41;
  let transferId = 0;
  let failPutRecordIndex: number | undefined;
  const records = new Map<string, Uint8Array>();
  const fetchedRecordIndexes: number[] = [];
  const revocations = new Set<string>();
  const removed: string[] = [];
  let receiptUpdate = 0;
  let failReceiptUpdate: number | undefined;
  const receipts = new Map<
    string,
    {
      bytes: Uint8Array;
      leaseExpiresAt?: number;
      leaseId?: string;
      version: number;
    }
  >();
  const receiptStore: SecureTransferProtectedReceiptStore = {
    id: "memory-receipts",
    acquire: async ({ leaseExpiresAt, leaseId, now, receiptId }) => {
      const value = receipts.get(receiptId);
      if (value === undefined) return { status: "missing" };
      if (
        value.leaseId !== undefined &&
        value.leaseId !== leaseId &&
        (value.leaseExpiresAt ?? 0) > now
      )
        return { status: "busy" };
      value.leaseId = leaseId;
      value.leaseExpiresAt = leaseExpiresAt;
      return {
        protectedBytes: value.bytes.slice(),
        status: "acquired",
        version: String(value.version),
      };
    },
    create: async ({ protectedBytes, receiptId }) => {
      if (receipts.has(receiptId)) return "exists";
      receipts.set(receiptId, { bytes: protectedBytes.slice(), version: 0 });
      return "created";
    },
    release: async ({ leaseId, now, receiptId, version }) => {
      const value = receipts.get(receiptId);
      if (
        value !== undefined &&
        value.leaseId === leaseId &&
        (value.leaseExpiresAt ?? 0) > now &&
        value.version === Number(version)
      ) {
        delete value.leaseId;
        delete value.leaseExpiresAt;
      }
    },
    remove: async ({ leaseId, now, receiptId, version }) => {
      const value = receipts.get(receiptId);
      if (
        value === undefined ||
        value.leaseId !== leaseId ||
        (value.leaseExpiresAt ?? 0) <= now ||
        value.version !== Number(version)
      )
        return "conflict";
      receipts.delete(receiptId);
      return "removed";
    },
    update: async ({
      leaseExpiresAt,
      leaseId,
      now,
      protectedBytes,
      receiptId,
      version,
    }) => {
      receiptUpdate += 1;
      const value = receipts.get(receiptId);
      if (
        failReceiptUpdate === receiptUpdate ||
        value === undefined ||
        value.leaseId !== leaseId ||
        (value.leaseExpiresAt ?? 0) <= now ||
        value.version !== Number(version)
      )
        return { status: "conflict" };
      value.bytes = protectedBytes.slice();
      value.leaseExpiresAt = leaseExpiresAt;
      value.version += 1;
      return { status: "updated", version: String(value.version) };
    },
  };
  const receiptProtector: SecureTransferReceiptProtector = {
    id: "xor-test-only",
    open: async ({ protectedBytes }) =>
      Uint8Array.from(protectedBytes, (byte) => byte ^ 0xa5),
    protect: async ({ plaintext }) =>
      Uint8Array.from(plaintext, (byte) => byte ^ 0xa5),
  };
  const store: SecureTransferStore = {
    id: "memory-store",
    getRecord: async ({ recordIndex, transferId }) => {
      fetchedRecordIndexes.push(recordIndex);
      return records.get(`${transferId}:${recordIndex}`)?.slice();
    },
    putRecord: async ({ bytes, recordIndex, transferId }) => {
      if (recordIndex === failPutRecordIndex)
        throw new Error("simulated crash");
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
  const revocationKey = (transferId: string, descriptorHash: Uint8Array) =>
    `${transferId}:${Buffer.from(descriptorHash).toString("hex")}`;
  const revocationStore: SecureTransferRevocationStore = {
    id: "memory-revocations",
    has: async ({ descriptorHash, transferId }) =>
      revocations.has(revocationKey(transferId, descriptorHash)),
    put: async ({ descriptorHash, transferId }) => {
      const key = revocationKey(transferId, descriptorHash);
      if (revocations.has(key)) return "exists";
      revocations.add(key);
      return "created";
    },
  };
  const provider: SecureTransferCryptoProvider = {
    id: "test.crypto",
    maximumRecordCiphertextBytes: 9,
    maximumRecordPlaintextBytes: 8,
    protocol: "TEST-1",
    createCapability: async () => ({
      bytes: Uint8Array.of((capabilityId += 1)),
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
    resumable: {
      leaseDurationMs: 100,
      ...(useDefaultIdFactories
        ? {}
        : { leaseIdFactory: () => `lease-${receiptUpdate}` }),
      protector: receiptProtector,
      ...(useDefaultIdFactories ? {} : { receiptIdFactory: () => "receipt-1" }),
      store: receiptStore,
    },
    revocations: revocationStore,
    store,
    ...(useDefaultIdFactories
      ? {}
      : { transferIdFactory: () => `transfer-${(transferId += 1)}` }),
  });
  return {
    client,
    fetchedRecordIndexes,
    records,
    receiptStore,
    receipts,
    removed,
    revocations,
    setFailReceiptUpdate: (value: number | undefined) => {
      failReceiptUpdate = value;
    },
    setFailPutRecordIndex: (value: number | undefined) => {
      failPutRecordIndex = value;
    },
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

const resumableMetadata = {
  attachmentId: "attachment-1",
  byteLength: 9,
  contentType: "application/octet-stream",
  conversationId: "conversation-1",
  expiresAt: 1_500,
  fileName: "private.bin",
  senderDeviceId: "alice-phone",
} as const;

const resumableSource = async (offset: number) =>
  Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9).slice(offset);

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

  test("authenticates only the records covering an exact plaintext range", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    const staged: Uint8Array[] = [];
    const offsets: number[] = [];
    let committedRange: { start: number; endExclusive: number } | undefined;
    await surface.client.downloadRange(
      descriptor,
      { start: 2, endExclusive: 8 },
      {
        abort: async () => {
          staged.length = 0;
        },
        commit: async (_value, range) => {
          committedRange = range;
        },
        write: async (bytes, _recordIndex, plaintextOffset) => {
          staged.push(bytes.slice());
          offsets.push(plaintextOffset);
        },
      },
    );
    expect(surface.fetchedRecordIndexes).toEqual([0, 1]);
    expect(offsets).toEqual([2, 4]);
    expect([...staged.flatMap((bytes) => [...bytes])]).toEqual([
      3, 4, 5, 6, 7, 8,
    ]);
    expect(committedRange).toEqual({ start: 2, endExclusive: 8 });
  });

  test("aborts range output on authentication failure and rejects invalid ranges", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    surface.records.get("transfer-1:1")![0] = 9;
    let aborted = 0;
    let committed = false;
    const sink = {
      abort: async () => {
        aborted += 1;
      },
      commit: async () => {
        committed = true;
      },
      write: async () => undefined,
    };
    await expect(
      surface.client.downloadRange(
        descriptor,
        { start: 3, endExclusive: 6 },
        sink,
      ),
    ).rejects.toThrow("context mismatch");
    await expect(
      surface.client.downloadRange(
        descriptor,
        { start: 4, endExclusive: 4 },
        sink,
      ),
    ).rejects.toThrow("non-empty");
    await expect(
      surface.client.downloadRange(
        descriptor,
        { start: 8, endExclusive: 10 },
        sink,
      ),
    ).rejects.toThrow("within the plaintext");
    expect({ aborted, committed }).toEqual({ aborted: 3, committed: false });
  });

  test("creates strict revocation notices and blocks future cooperating downloads", async () => {
    const surface = createSurface();
    const descriptor = await upload(surface);
    const result = await surface.client.revoke({
      descriptor,
      reason: "member-removed",
      revokerDeviceId: "alice-phone",
    });
    expect(result.ciphertextRemoved).toBe(true);
    expect(surface.records.size).toBe(0);
    expect(surface.revocations.size).toBe(1);

    const encoded = encodeSecureTransferRevocation(result.revocation);
    const decoded = decodeSecureTransferRevocation(encoded, 1_024);
    expect(decoded).toEqual(result.revocation);
    const extended = new TextEncoder().encode(
      JSON.stringify({
        ...JSON.parse(new TextDecoder().decode(encoded)),
        eraseEveryCopy: true,
      }),
    );
    expect(() => decodeSecureTransferRevocation(extended, 1_024)).toThrow(
      "unknown fields",
    );

    let aborted = false;
    await expect(
      surface.client.download(descriptor, {
        abort: async () => {
          aborted = true;
        },
        commit: async () => undefined,
        write: async () => undefined,
      }),
    ).rejects.toThrow("revoked");
    expect(aborted).toBe(true);
  });

  test("applies only descriptor-bound revocations after caller authorization", async () => {
    const sender = createSurface();
    const descriptor = await upload(sender);
    const { revocation } = await sender.client.revoke({
      descriptor,
      revokerDeviceId: "alice-phone",
    });
    const recipient = createSurface();
    await expect(
      recipient.client.applyRevocation({ descriptor, revocation }),
    ).resolves.toBe("created");
    const wrongHash = revocation.descriptorHash.slice();
    wrongHash[0] = (wrongHash[0] ?? 0) ^ 1;
    await expect(
      createSurface().client.applyRevocation({
        descriptor,
        revocation: { ...revocation, descriptorHash: wrongHash },
      }),
    ).rejects.toThrow("hash does not match");
  });

  test("rotates an attachment into one epoch-bound replacement payload", async () => {
    const surface = createSurface();
    const previousDescriptor = await upload(surface);
    const replacement = await surface.client.prepareReplacement({
      previousDescriptor,
      reason: "membership-change",
      replacement: {
        attachmentId: previousDescriptor.attachmentId,
        body: Uint8Array.of(9, 8, 7, 6, 5, 4, 3, 2, 1),
        byteLength: 9,
        conversationId: previousDescriptor.conversationId,
        expiresAt: 1_600,
        senderDeviceId: "alice-phone",
      },
      securityEpoch: 2,
    });
    expect(replacement.replacementDescriptor.transferId).toBe("transfer-2");
    expect(replacement.replacementDescriptor.capability.bytes).not.toEqual(
      previousDescriptor.capability.bytes,
    );

    const encoded = encodeSecureTransferReplacement(replacement);
    const decoded = decodeSecureTransferReplacement(encoded, 4_096, 2_048);
    expect(decoded).toEqual(replacement);
    const extended = new TextEncoder().encode(
      JSON.stringify({
        ...JSON.parse(new TextDecoder().decode(encoded)),
        keepFormerMember: true,
      }),
    );
    expect(() =>
      decodeSecureTransferReplacement(extended, 4_096, 2_048),
    ).toThrow("unknown fields");

    let persisted: string | undefined;
    const activated = await surface.client.activateReplacement({
      authenticatedContext: {
        conversationId: "conversation-1",
        purpose: "secure-transfer.replacement",
        securityEpoch: 2,
        senderId: "alice-phone",
      },
      persistReplacement: async (descriptor) => {
        expect(surface.revocations.size).toBe(0);
        persisted = descriptor.transferId;
      },
      previousDescriptor,
      removeSupersededCiphertext: true,
      replacement: decoded,
    });
    expect(persisted).toBe("transfer-2");
    expect(activated).toEqual({
      ciphertextRemoved: true,
      revocation: "created",
    });
    expect(
      [...surface.records.keys()].every((key) => key.startsWith("transfer-2:")),
    ).toBe(true);
  });

  test("rejects replacement activation outside its authenticated MLS epoch", async () => {
    const surface = createSurface();
    const previousDescriptor = await upload(surface);
    const replacement = await surface.client.prepareReplacement({
      previousDescriptor,
      reason: "device-recovery",
      replacement: {
        attachmentId: previousDescriptor.attachmentId,
        body: Uint8Array.of(1),
        byteLength: 1,
        conversationId: previousDescriptor.conversationId,
        expiresAt: 1_600,
        senderDeviceId: "alice-phone",
      },
      securityEpoch: 3,
    });
    let persisted = false;
    await expect(
      surface.client.activateReplacement({
        authenticatedContext: {
          conversationId: "conversation-1",
          purpose: "secure-transfer.replacement",
          securityEpoch: 4,
          senderId: "alice-phone",
        },
        persistReplacement: async () => {
          persisted = true;
        },
        previousDescriptor,
        replacement,
      }),
    ).rejects.toThrow("MLS epoch");
    expect(persisted).toBe(false);
    expect(surface.revocations.size).toBe(0);
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

  test("persists only protected, strict resumable receipts", async () => {
    const surface = createSurface();
    await surface.client.beginResumableUpload(resumableMetadata);
    const protectedBytes = surface.receipts.get("receipt-1")!.bytes;
    expect(new TextDecoder().decode(protectedBytes)).not.toContain(
      "private.bin",
    );
    const plaintext = Uint8Array.from(protectedBytes, (byte) => byte ^ 0xa5);
    const receipt = decodeSecureTransferUploadReceipt(plaintext, 4_096, 2_048);
    expect(receipt.nextRecordIndex).toBe(0);
    expect(receipt.phase).toBe("ready");
    expect(
      decodeSecureTransferUploadReceipt(
        encodeSecureTransferUploadReceipt(receipt),
        4_096,
        2_048,
      ),
    ).toEqual(receipt);
    const extended = new TextEncoder().encode(
      JSON.stringify({
        ...JSON.parse(
          new TextDecoder().decode(encodeSecureTransferUploadReceipt(receipt)),
        ),
        capability: "smuggled",
      }),
    );
    expect(() =>
      decodeSecureTransferUploadReceipt(extended, 4_096, 2_048),
    ).toThrow("unknown fields");
  });

  test("recovers after ciphertext creation but before its receipt checkpoint", async () => {
    const surface = createSurface();
    await surface.client.beginResumableUpload(resumableMetadata);
    surface.setFailReceiptUpdate(2);
    await expect(
      surface.client.resumeUpload({
        receiptId: "receipt-1",
        source: resumableSource,
      }),
    ).rejects.toThrow("checkpoint");
    expect(surface.records.has("transfer-1:0")).toBe(true);

    surface.setFailReceiptUpdate(undefined);
    const descriptor = await surface.client.resumeUpload({
      receiptId: "receipt-1",
      source: resumableSource,
    });
    expect(descriptor.recordCount).toBe(3);
    expect(surface.receipts.has("receipt-1")).toBe(false);
    expect(surface.records.size).toBe(3);
  });

  test("refuses nonce reuse when encryption may have run without durable ciphertext", async () => {
    const surface = createSurface();
    await surface.client.beginResumableUpload(resumableMetadata);
    surface.setFailPutRecordIndex(0);
    await expect(
      surface.client.resumeUpload({
        receiptId: "receipt-1",
        source: resumableSource,
      }),
    ).rejects.toThrow("simulated crash");
    surface.setFailPutRecordIndex(undefined);
    await expect(
      surface.client.resumeUpload({
        receiptId: "receipt-1",
        source: resumableSource,
      }),
    ).rejects.toBeInstanceOf(SecureTransferResumeUnsafeError);
    expect(surface.records.size).toBe(0);
  });

  test("rejects concurrent resumptions while a receipt lease is live", async () => {
    const surface = createSurface();
    await surface.client.beginResumableUpload(resumableMetadata);
    expect(
      await surface.receiptStore.acquire({
        leaseExpiresAt: 1_050,
        leaseId: "other-agent",
        now: 1_000,
        receiptId: "receipt-1",
      }),
    ).toMatchObject({ status: "acquired" });
    await expect(
      surface.client.resumeUpload({
        receiptId: "receipt-1",
        source: resumableSource,
      }),
    ).rejects.toThrow("already leased");
  });

  test("uses receiver-safe default UUID factories", async () => {
    const surface = createSurface(true);
    const descriptor = await upload(surface);
    expect(descriptor.transferId).toMatch(/^[0-9a-f-]{36}$/u);
    const handle = await surface.client.beginResumableUpload(resumableMetadata);
    expect(handle.receiptId).toMatch(/^[0-9a-f-]{36}$/u);
  });
});
