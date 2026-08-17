import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = resolve(root, "data/reason");
const defaultBinary = resolve(root, "../target/debug/reason");
const reason = process.env.REASON_BIN || defaultBinary;

await access(reason, constants.X_OK);
const base = JSON.parse(await readFile(resolve(dataDir, "authorized-request.json"), "utf8"));
const clone = value => structuredClone(value);

function withActionId(request, id) {
  request.action.id = id;
  request.policy.query.arguments = [id];
  return request;
}

const unknown = withActionId(clone(base), "action_deploy_unknown");
unknown.policy.facts = unknown.policy.facts.filter(fact => fact.id !== "fact_approval_140");

const denied = withActionId(clone(base), "action_deploy_denied");
for (const fact of denied.policy.facts) {
  if (fact.id === "fact_approval_140") {
    fact.id = "fact_rejection_140";
    fact.negated = true;
  }
}

const conflict = withActionId(clone(base), "action_deploy_conflict");
const rejection = clone(conflict.policy.facts.find(fact => fact.id === "fact_approval_140"));
rejection.id = "fact_rejection_140";
rejection.negated = true;
conflict.policy.facts.push(rejection);

const scenarios = {
  authorized: { request: base, exit: 0, status: "authorized" },
  unknown: { request: unknown, exit: 2, status: "insufficient_evidence" },
  denied: { request: denied, exit: 3, status: "denied" },
  conflict: { request: conflict, exit: 4, status: "conflicted" },
};

function run(args, expectedExit) {
  const result = spawnSync(reason, args, { cwd: root, encoding: "utf8" });
  if (result.status !== expectedExit) {
    throw new Error(`${reason} ${args.join(" ")} exited ${result.status}; expected ${expectedExit}\n${result.stderr}`);
  }
  return result.stdout;
}

const manifest = { schema: "zerker.demo.reason-fixtures.v1", generator: run(["--version"], 0).trim(), scenarios: {} };
for (const [name, scenario] of Object.entries(scenarios)) {
  const requestPath = resolve(dataDir, `${name}-request.json`);
  const certificatePath = resolve(dataDir, `${name}-certificate.json`);
  const verificationPath = resolve(dataDir, `${name}-verification.json`);
  await writeFile(requestPath, `${JSON.stringify(scenario.request, null, 2)}\n`);
  run(["--format", "json", "authorize", requestPath, "--certificate-out", certificatePath], scenario.exit);
  const verificationJson = run(["--format", "json", "verify-authorization", requestPath, certificatePath], 0);
  await writeFile(verificationPath, verificationJson);
  const certificate = JSON.parse(await readFile(certificatePath, "utf8"));
  const verification = JSON.parse(verificationJson);
  if (certificate.status !== scenario.status || verification.status !== "verified") {
    throw new Error(`${name}: generated certificate did not match expected status`);
  }
  const artifacts = {};
  for (const [kind, path] of Object.entries({ request: requestPath, certificate: certificatePath, verification: verificationPath })) {
    artifacts[kind] = `sha256:${createHash("sha256").update(await readFile(path)).digest("hex")}`;
  }
  manifest.scenarios[name] = { status: certificate.status, authorize_exit: scenario.exit, request_digest: certificate.request_digest, artifacts };
  console.log(`${name.padEnd(10)} ${certificate.status.padEnd(22)} ${certificate.request_digest}`);
}
await writeFile(resolve(dataDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
