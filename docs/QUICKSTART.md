# Deployment authorization quickstart

This walkthrough checks whether an AI agent may deploy one exact commit to production, writes an authorization certificate, and verifies that certificate independently.

## Install the developer preview

### Download a release binary

Download the archive for your platform from the [`v0.1.0` release](https://github.com/zerkerlabs/reason/releases/tag/v0.1.0), then verify its checksum:

```bash
shasum -a 256 -c zerker-reason-v0.1.0-*.tar.gz.sha256
tar -xzf zerker-reason-v0.1.0-*.tar.gz
install -m 0755 reason ~/.local/bin/reason
reason --version
```

Release archives are produced for:

- macOS arm64;
- macOS x86_64;
- Linux x86_64.

### Build from source

Rust 1.85 or newer is required.

```bash
git clone https://github.com/zerkerlabs/reason.git
cd reason
cargo build --release --locked
./target/release/reason --version
```

## Authorize the deployment

The example binds the mission, exact tool name, normalized arguments, declared effect, governed release evidence, authority policy, and evaluation time.

```bash
reason authorize examples/authorize-deploy.json \
  --certificate-out authorization.json
```

Expected decision:

```text
AUTHORIZED  action_deploy_140 via mission_release_140
            deploy_release(commit=commit_abc, environment=production, version=1.4.0)
```

Only `authorized` exits with code `0`. Missing evidence exits `2`, explicit denial exits `3`, and conflict exits `4`.

## Verify independently

```bash
reason verify-authorization \
  examples/authorize-deploy.json \
  authorization.json
```

Expected result:

```text
VERIFIED_AUTHORIZATION  sha256:... (authorized)
```

Change the commit, environment, tool, effect, policy, evidence, or evaluation snapshot and verification fails.

## Exercise fail-closed outcomes

```bash
reason check examples/release-blocked.json       # unknown, exit 2
reason check examples/release-disproved.json     # disproved, exit 3
reason check examples/release-inconsistent.json  # inconsistent, exit 4
reason check examples/release-expired.json       # stale evidence, exit 2
reason check examples/release-wrong-commit.json  # evidence does not match action
```

Unknown is not false. Conflict is not permission. Neither may cross an authorization boundary.

## Preserve the certificate with Treeship

If the Treeship CLI is available next to the Reason repository:

```bash
cargo build --manifest-path ../treeship/Cargo.toml -p treeship-cli
TREESHIP_BIN=../treeship/target/debug/treeship \
  ./scripts/reason-treeship-e2e.sh
```

Reason verifies the authorization semantics. Treeship separately verifies the signed byte commitment, signer key, and artifact chain. Run both verifiers.

## Use JSON in an agent workflow

```bash
reason --format json authorize examples/authorize-deploy.json \
  --certificate-out authorization.json
```

Treat only `status: "authorized"` with exit code `0` as permission to continue. An enforcement layer such as Guard must still bind execution to the exact certified action.
