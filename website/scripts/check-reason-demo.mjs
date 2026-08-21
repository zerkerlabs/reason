import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = resolve(root, "data/reason");
const binary = process.env.REASON_BIN || resolve(root, "../target/debug/reason");
const expected = {
  authorized: "authorized",
  unknown: "insufficient_evidence",
  denied: "denied",
  conflict: "conflicted",
};

let canReplay = true;
try { await access(binary, constants.X_OK); } catch { canReplay = false; }
const manifest = JSON.parse(await readFile(resolve(dataDir, "manifest.json"), "utf8"));
if (manifest.schema !== "zerker.demo.reason-fixtures.v1") throw new Error("wrong fixture manifest schema");

const index = await readFile(resolve(root, "index.html"), "utf8");
const styles = await readFile(resolve(root, "styles.css"), "utf8");
const vercel = JSON.parse(await readFile(resolve(root, "vercel.json"), "utf8"));
if (!index.includes('<base href="/reason/" />') || !index.includes('rel="canonical" href="https://zerker.ai/reason"')) {
  throw new Error("Reason must use the canonical zerker.ai/reason base path");
}
if (index.includes("fonts.googleapis.com") || index.includes("fonts.gstatic.com")) {
  throw new Error("Reason must not require third-party font hosts");
}
for (const font of ["geist-variable.woff2", "geist-mono-variable.woff2"]) {
  if (!styles.includes(`assets/fonts/${font}`)) throw new Error(`${font} is not declared`);
  await access(resolve(root, `dist/assets/fonts/${font}`));
}
const expectedRewrites = [
  { source: "/reason", destination: "/" },
  { source: "/reason/:path(.*)", destination: "/:path" },
];
if (JSON.stringify(vercel.rewrites) !== JSON.stringify(expectedRewrites)) {
  throw new Error("Reason deployment must serve its complete canonical subpath without clean-URL drift");
}

for (const [name, status] of Object.entries(expected)) {
  const requestPath = resolve(dataDir, `${name}-request.json`);
  const certificatePath = resolve(dataDir, `${name}-certificate.json`);
  const verificationPath = resolve(dataDir, `${name}-verification.json`);
  const paths = { request: requestPath, certificate: certificatePath, verification: verificationPath };
  const raw = Object.fromEntries(await Promise.all(Object.entries(paths).map(async ([kind, path]) => [kind, await readFile(path)])));
  const [request, certificate, verification] = [raw.request, raw.certificate, raw.verification].map(value => JSON.parse(value));
  for (const [kind, bytes] of Object.entries(raw)) {
    const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    if (manifest.scenarios[name]?.artifacts?.[kind] !== digest) throw new Error(`${name}: ${kind} bytes do not match manifest`);
  }
  if (certificate.schema !== "zerker.reason.authorization.v1") throw new Error(`${name}: wrong certificate schema`);
  if (certificate.status !== status) throw new Error(`${name}: expected ${status}, got ${certificate.status}`);
  if (verification.schema !== "zerker.reason.authorization-verification.v1" || verification.status !== "verified") {
    throw new Error(`${name}: invalid bundled verification result`);
  }
  if (verification.request_digest !== certificate.request_digest || verification.authorization_status !== certificate.status) {
    throw new Error(`${name}: certificate and verification are not bound to the same result`);
  }
  if (request.action.id !== certificate.action.id || request.policy.query.arguments[0] !== certificate.action.id) {
    throw new Error(`${name}: action identity drifted`);
  }
  await Promise.all(["request", "certificate", "verification"].map(kind => access(resolve(root, `dist/data/reason/${name}-${kind}.json`))));
  await access(resolve(root, "dist/data/reason/manifest.json"));
  if (canReplay) {
    const replay = spawnSync(binary, ["--format", "json", "verify-authorization", requestPath, certificatePath], { encoding: "utf8" });
    if (replay.status !== 0 || JSON.parse(replay.stdout).status !== "verified") throw new Error(`${name}: independent replay failed`);
  }
  console.log(`${name.padEnd(10)} ${status.padEnd(22)} ${canReplay ? "replayed" : "bundled verification checked"}`);
}
