import { expect, test } from "bun:test";
import { readdir } from "node:fs/promises";

test("public TypeScript source uses type aliases rather than interfaces", async () => {
  const files = (await readdir(new URL("../src", import.meta.url))).filter(
    (file) => file.endsWith(".ts"),
  );
  for (const file of files) {
    const source = await Bun.file(
      new URL(`../src/${file}`, import.meta.url),
    ).text();
    expect(source).not.toMatch(/\binterface\s+[A-Za-z_$]/);
  }
});
