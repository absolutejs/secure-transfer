import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<{
  maximumAttachmentBytes?: number;
  maximumRecordPlaintextBytes?: number;
  maximumTtlMs?: number;
}>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "security-teams", "agent-hosts"],
    intents: [
      "encrypt a large attachment before untrusted object storage",
      "stream authenticated records into an atomic destination",
      "send a private attachment descriptor through secure messaging",
      "detect missing reordered substituted or truncated transfer records",
    ],
    keywords: [
      "secure transfer",
      "encrypted attachment",
      "large object",
      "record encryption",
      "untrusted storage",
    ],
    protocols: ["RFC 8188-inspired authenticated records"],
  },
  identity: {
    accent: "#0f766e",
    category: "security",
    description:
      "Provider-neutral encrypted large-object transfer with bounded records, strict descriptors, and transactional download sinks.",
    docsUrl: "https://github.com/absolutejs/secure-transfer",
    name: "@absolutejs/secure-transfer",
    tagline: "Move large encrypted objects without trusting storage.",
  },
  settings: Type.Object(
    {
      maximumAttachmentBytes: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum attachment bytes" }),
      ),
      maximumRecordPlaintextBytes: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum record bytes" }),
      ),
      maximumTtlMs: Type.Optional(
        Type.Integer({ minimum: 1, title: "Maximum transfer lifetime" }),
      ),
    },
    { additionalProperties: false },
  ),
  wiring: [],
});
