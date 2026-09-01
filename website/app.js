const app = document.querySelector("#app");

const icons = {
  arrow: `<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10h11M11 6l4 4-4 4"/></svg>`,
  shield: `<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 2.5 16 5v4.3c0 3.8-2.3 6.5-6 8.2-3.7-1.7-6-4.4-6-8.2V5l6-2.5Z"/><path d="m7.5 10 1.7 1.7 3.6-4"/></svg>`,
  receipt: `<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2.5h10v15l-2.5-1.5-2.5 1.5L7.5 16 5 17.5v-15Z"/><path d="M8 7h4M8 10h4"/></svg>`,
  file: `<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 2.5h6l4 4v11H5z"/><path d="M11 2.5v4h4M8 10h4M8 13h4"/></svg>`,
};

function mark(label = "ZERKER", productBrand = false) {
  const productAttribute = productBrand ? " data-zk-product-brand" : "";
  return `<a class="wordmark"${productAttribute} href="/reason" aria-label="Zerker Reason home"><span class="mark-glyph"><i></i><i></i></span><b>${label}</b></a>`;
}

function page() {
  return `<main class="zr-shell">
    <nav class="zr-nav" aria-label="Reason navigation">
      <div class="zr-brand">${mark("ZERKER", true)}<i></i><span>REASON</span></div>
      <div class="zr-nav-links">
        <button type="button" data-zr-scroll="zr-policy">Organization policy</button>
        <button type="button" data-zr-scroll="zr-demo">Decision demo</button>
        <a href="https://github.com/zerkerlabs/reason">GitHub</a>
      </div>
      <button class="zr-nav-cta" type="button" data-zr-scroll="zr-start">Run locally</button>
    </nav>

    <header class="zr-hero">
      <div class="zr-copy">
        <p>NEUROSYMBOLIC AUTHORIZATION FOR AI AGENTS</p>
        <h1>Company rules,<br><strong>enforced before agents act.</strong></h1>
        <span>Models handle ambiguous work. Reason checks the proposed action against governed facts, explicit rules, authority, and time. When Reason enforcement is configured, Gateway forwards only the exact independently verified MCP call.</span>
        <div class="zr-copy-actions">
          <button class="zr-primary" type="button" data-zr-scroll="zr-demo">See the decision ${icons.arrow}</button>
          <a href="https://github.com/zerkerlabs/reason">View the source</a>
        </div>
        <small>Open source · local first · deterministic · v0.3</small>
      </div>

      <div class="zr-proof" aria-label="Governed facts and an exact action evaluated by Zerker Reason">
        <div class="zr-proof-head"><span>EXACT-ACTION CHECK</span><code>zerker.reason.action.v1</code></div>
        <div class="zr-proof-action"><span>PROPOSED ACTION</span><strong>deploy_release</strong><code>commit_abc · production</code></div>
        <div class="zr-proof-inputs">
          <div><span>GOVERNED FACT</span><b>tests_passed(commit_abc)</b></div>
          <div><span>COMPANY RULE</span><b>production_release.v4</b></div>
          <div><span>AUTHORITY + TIME</span><b>release-owner · current</b></div>
        </div>
        <div class="zr-proof-gate"><i></i><div class="zr-proof-mark"><span class="mark-glyph"><i></i><i></i></span></div><i></i></div>
        <div class="zr-proof-result"><span>DETERMINISTIC RESULT</span><strong>PROVED</strong><p>Exact action authorized</p><code>proof sha256:ba4bd9…c6eaf</code></div>
        <div class="zr-proof-foot">${icons.receipt}<span><b>Authorization certificate</b><small>Independently verifiable</small></span></div>
      </div>
    </header>

    <section class="zr-policy" id="zr-policy">
      <div class="zr-section-head">
        <div><p>ORGANIZATION POLICY LAYER</p><h2>One policy bundle for every agent tool.</h2></div>
        <span>Teams should not have to duplicate company rules for every model vendor and coding agent.</span>
      </div>

      <div class="zr-policy-map">
        <article class="zr-policy-sources">
          <small>HUMAN-READABLE SOURCES</small>
          <h3>Keep the files teams already use.</h3>
          <ul><li>${icons.file}<span>AGENTS.md</span></li><li>${icons.file}<span>CLAUDE.md</span></li><li>${icons.file}<span>.agents/skills/**</span></li><li>${icons.file}<span>security-policy.md</span></li></ul>
        </article>
        <div class="zr-policy-arrow"><span>resolve + review</span>→</div>
        <article class="zr-policy-bundle">
          <small>GOVERNED POLICY BUNDLE</small>
          <h3>One reviewed contract.</h3>
          <dl><div><dt>sources</dt><dd>digest-bound</dd></div><div><dt>rules</dt><dd>typed + versioned</dd></div><div><dt>facts</dt><dd>authority-aware</dd></div><div><dt>time</dt><dd>explicit validity</dd></div></dl>
          <code>bundle sha256:7ab41e…192c</code>
        </article>
        <div class="zr-policy-arrow"><span>bind to action</span>→</div>
        <article class="zr-policy-gate">
          <small>ENFORCEMENT BOUNDARY</small>
          <h3>Proof or no action.</h3>
          <div><b>AUTHORIZED</b><span>matching call can proceed</span></div>
          <div><b>UNKNOWN</b><span>missing evidence blocks</span></div>
          <div><b>CONFLICT</b><span>escalate, never guess</span></div>
        </article>
      </div>

      <div class="zr-boundary-note">
        <span>PRODUCT BOUNDARY</span>
        <p><strong>Reason evaluates reviewed typed policy and commits the exact bytes of your sources.</strong> It does not interpret instruction files into policy, and it cannot prove a model read them. Compiling written policy into reviewed rules is product direction.</p>
      </div>
    </section>

    <section class="zr-use-cases">
      <div class="zr-section-head">
        <div><p>COMPANY USE CASES</p><h2>Govern the action that creates risk.</h2></div>
        <span>Release safety is the first complete workflow. The same exact-action contract can support additional reviewed domain packs.</span>
      </div>
      <div class="zr-use-list">
        <article><span>01</span><div><h3>Software delivery</h3><p>Can this exact commit and artifact deploy to this environment?</p></div><small>tests · artifact · review · approval · time</small></article>
        <article><span>02</span><div><h3>MCP and tool access</h3><p>Can this principal call this tool with these exact arguments?</p></div><small>identity · tenant · agent · tool · arguments</small></article>
        <article><span>03</span><div><h3>Data handling</h3><p>Can this agent send these fields to this destination for this purpose?</p></div><small>classification · consent · region · retention</small></article>
        <article><span>04</span><div><h3>Financial operations</h3><p>Can this agent refund, purchase, or transfer this amount?</p></div><small>limit · budget · counterparty · approval</small></article>
        <article><span>05</span><div><h3>Customer operations</h3><p>Can this agent change this account, subscription, or entitlement?</p></div><small>ownership · contract · case state · consent</small></article>
        <article><span>06</span><div><h3>Delegated agents</h3><p>Can this sub-agent act inside the parent mission's scope?</p></div><small>mission · delegation · effect · expiration</small></article>
      </div>
      <p class="zr-use-note">Row 01 is the first complete workflow. Rows 02–06 are authorization patterns the same exact-action contract supports; quantitative and regulated checks need trusted evidence adapters or additional solver primitives.</p>
    </section>

    <section class="zr-demo" id="zr-demo">
      <div class="zr-section-head zr-section-head-dark">
        <div><p>VERIFIED FIXTURE</p><h2>Should this agent deploy?</h2></div>
        <span>Change the evidence. Only a proven yes is eligible for enforcement.</span>
      </div>
      <div class="zr-demo-shell">
        <div class="zr-demo-tabs" role="group" aria-label="Release evidence scenario">
          <button type="button" class="active" data-zr-state="authorized" aria-pressed="true"><i></i>All clear</button>
          <button type="button" data-zr-state="unknown" aria-pressed="false"><i></i>Approval missing</button>
          <button type="button" data-zr-state="denied" aria-pressed="false"><i></i>Release rejected</button>
          <button type="button" data-zr-state="conflict" aria-pressed="false"><i></i>Evidence conflicts</button>
        </div>
        <div class="zr-demo-grid">
          <article class="zr-request-card">
            <small>EXACT AGENT ACTION</small><h3>Deploy version 1.4.0 to production.</h3>
            <dl><div><dt>commit</dt><dd>commit_abc</dd></div><div><dt>tool</dt><dd>deploy_release</dd></div><div><dt>principal</dt><dd>release-agent</dd></div></dl>
            <div class="zr-evidence"><span>GOVERNED EVIDENCE</span><p><i class="ok"></i>Tests passed for this commit</p><p><i class="ok"></i>Security review is current</p><p data-zr-approval><i class="ok"></i>Release owner approved</p></div>
          </article>
          <div class="zr-demo-aperture" aria-hidden="true"><i></i><span class="mark-glyph"><i></i><i></i></span><i></i></div>
          <article class="zr-outcome authorized" data-zr-card aria-live="polite">
            <small data-zr-label>AUTHORIZED</small><strong data-zr-verdict>DEPLOY</strong><h3 data-zr-title>Yes. Deploy this commit.</h3><p data-zr-detail>Every required fact is present and trusted.</p><div class="zr-consequence" data-zr-consequence>This exact deployment is eligible for enforcement.</div>
            <dl><div><dt>RESULT</dt><dd data-zr-result>authorized</dd></div><div><dt>EXIT</dt><dd data-zr-exit>0</dd></div><div><dt>REQUEST</dt><dd data-zr-digest>sha256:ffbb68…7c8d5</dd></div></dl>
          </article>
        </div>
        <div class="zr-verification-bar">${icons.shield}<div><b data-zr-foot>Certificate verified · authorized</b><span data-zr-source>reason 0.2.0 · fixture bytes match SHA-256 manifest</span></div><a data-zr-certificate-link href="/reason/data/reason/authorized-certificate.json" download>Download certificate ${icons.arrow}</a></div>
        <details class="zr-dev-proof"><summary>View the developer proof</summary><div class="zr-terminal"><pre data-zr-command><em>$</em> reason authorize data/reason/authorized-request.json

<span>AUTHORIZED</span>  action_deploy_140
            deploy_release(commit_abc, production)
            proof sha256:ba4bd9…c6eaf

<small>Exit 0 · certificate independently verified</small></pre></div></details>
      </div>
    </section>

    <section class="zr-model">
      <div class="zr-section-head">
        <div><p>NEURAL + SYMBOLIC</p><h2>Use judgment to propose. Use proof to authorize.</h2></div>
        <span>The symbolic layer does not replace the model. It limits what a probabilistic system may cause in the world.</span>
      </div>
      <div class="zr-path">
        <article><small>01 · PROPOSE</small><h3>Neural model</h3><p>Interprets language, plans work, and proposes an exact action.</p></article>
        <i>→</i>
        <article><small>02 · ADMIT</small><h3>Governed evidence</h3><p>Only facts from accepted authorities enter the evaluation snapshot.</p></article>
        <i>→</i>
        <article><small>03 · DERIVE</small><h3>Reason kernel</h3><p>Evaluates explicit rules without turning missing evidence into permission.</p></article>
        <i>→</i>
        <article><small>04 · ENFORCE</small><h3>Gateway</h3><p>Compares the certificate with the concrete call and forwards only an exact match.</p></article>
      </div>
      <div class="zr-truth-grid">
        <article class="proved"><span>PROVED</span><p>Required support exists.</p><code>exit 0</code></article>
        <article><span>UNKNOWN</span><p>Required evidence is missing.</p><code>exit 2</code></article>
        <article class="denied"><span>DISPROVED</span><p>Explicit negative support exists.</p><code>exit 3</code></article>
        <article class="conflict"><span>INCONSISTENT</span><p>Trusted support exists on both sides.</p><code>exit 4</code></article>
      </div>
    </section>

    <section class="zr-gateway">
      <div class="zr-gateway-copy"><p>GATEWAY ENFORCEMENT TODAY</p><h2>The certificate must match the call.</h2><span>Gateway binds the verified mission to the authenticated principal, tenant, and agent. It compares the certified MCP tool and canonical arguments before payment, invocation creation, or forwarding.</span></div>
      <div class="zr-gateway-proof">
        <div class="zr-gateway-head"><span>POST /v1/proxy/{agent_id}</span><code>tools/call</code></div>
        <ol><li><span>01</span><p><b>Verify</b> the atomic Reason authorization bundle.</p></li><li><span>02</span><p><b>Bind</b> principal, tenant, and agent to authenticated context.</p></li><li><span>03</span><p><b>Compare</b> exact tool and canonical arguments.</p></li><li><span>04</span><p><b>Block</b> mismatch, denial, conflict, failure, or replay.</p></li></ol>
        <div class="zr-gateway-result"><span>VERIFIED + AUTHORIZED + EXACT MATCH</span><strong>FORWARD</strong></div>
        <small>Current scope: the caller supplies an atomic authorization bundle for transactional MCP <code>tools/call</code> when <code>ZERKER_REASON_BINARY</code> is configured. Gateway verifies and enforces the bundle; it does not automatically authorize raw calls. Streaming rejects Reason-enabled tool calls rather than bypassing enforcement.</small>
      </div>
    </section>

    <section class="zr-certificate-section">
      <div class="zr-section-head">
        <div><p>BOUND TO THE EXACT REQUEST</p><h2>Change one argument. Break the certificate.</h2></div>
        <span>Mission, tool, arguments, effects, policy, evidence, authority, and evaluation time are digest-bound.</span>
      </div>
      <pre data-zr-json>{
  <b>"schema"</b>: <em>"zerker.reason.authorization.v1"</em>,
  <b>"status"</b>: <em>"authorized"</em>,
  <b>"action"</b>: { <b>"tool"</b>: <em>"deploy_release"</em>, <b>"commit"</b>: <em>"commit_abc"</em> },
  <b>"request_digest"</b>: <em>"sha256:ffbb682242b1..."</em>,
  <b>"proof_digest"</b>: <em>"sha256:ba4bd960b803..."</em>
}</pre>
      <div class="zr-json-actions"><a data-zr-request-link href="/reason/data/reason/authorized-request.json" download>Download request ${icons.arrow}</a><a data-zr-verification-link href="/reason/data/reason/authorized-verification.json" download>Download verification ${icons.arrow}</a></div>
    </section>

    <section class="zr-start" id="zr-start">
      <div><p>RUN IT LOCALLY</p><h2>Inspect the decision yourself.</h2><span>No daemon, account, network, wall clock, or LLM is required for the symbolic check.</span><a href="https://github.com/zerkerlabs/reason">Read the repository ${icons.arrow}</a></div>
      <pre><i>$</i> cargo run -- authorize \\
  examples/authorize-deploy.json \\
  --certificate-out authorization.json
<i>$</i> cargo run -- verify-authorization \\
  examples/authorize-deploy.json authorization.json
<span>VERIFIED_AUTHORIZATION</span></pre>
    </section>

    <footer class="zr-footer"><div>${mark()}<i></i><span>REASON</span></div><p>Apache 2.0 · deterministic · local first</p><a href="https://zerker.ai/">Explore Zerker Gateway →</a></footer>
  </main>`;
}

const scenarios = {
  authorized: { label: "AUTHORIZED", verdict: "DEPLOY", title: "Yes. Deploy this commit.", detail: "Every required fact is present and trusted.", consequence: "This exact deployment is eligible for enforcement.", approval: "Release owner approved", evidenceTone: "ok", exit: "0", tone: "authorized" },
  unknown: { label: "BLOCKED", verdict: "WAIT", title: "Approval is missing.", detail: "Tests passed, but no trusted release-owner approval exists.", consequence: "The deployment stays blocked until an accepted authority approves it.", approval: "Release approval is missing", evidenceTone: "missing", exit: "2", tone: "unknown" },
  denied: { label: "BLOCKED", verdict: "STOP", title: "This release was rejected.", detail: "A trusted release authority explicitly rejected this deployment.", consequence: "The deployment tool will not run.", approval: "Release owner rejected", evidenceTone: "denied", exit: "3", tone: "denied" },
  conflict: { label: "BLOCKED", verdict: "STOP", title: "The evidence conflicts.", detail: "Trusted approval and trusted rejection both exist.", consequence: "The deployment stays blocked until the conflict is resolved.", approval: "Approved and rejected", evidenceTone: "conflict", exit: "4", tone: "conflict" },
};

const cache = new Map();
const shortDigest = value => value ? `${value.slice(0, 20)}…${value.slice(-6)}` : "none";
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);

async function fetchJsonWithDigest(url, expectedDigest) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} unavailable`);
  const bytes = await response.arrayBuffer();
  const digestBytes = await crypto.subtle.digest("SHA-256", bytes);
  const digest = `sha256:${[...new Uint8Array(digestBytes)].map(byte => byte.toString(16).padStart(2, "0")).join("")}`;
  if (digest !== expectedDigest) throw new Error(`${url} does not match fixture manifest`);
  return JSON.parse(new TextDecoder().decode(bytes));
}

async function loadScenario(key) {
  const scenario = scenarios[key];
  if (!scenario) return;
  document.querySelectorAll("[data-zr-state]").forEach(element => {
    const selected = element.dataset.zrState === key;
    element.classList.toggle("active", selected);
    element.setAttribute("aria-pressed", String(selected));
  });
  const card = document.querySelector("[data-zr-card]");
  if (card) card.className = `zr-outcome ${scenario.tone}`;
  try {
    let data = cache.get(key);
    if (!data) {
      const base = `/reason/data/reason/${key}`;
      const manifestResponse = await fetch("/reason/data/reason/manifest.json");
      if (!manifestResponse.ok) throw new Error("fixture manifest unavailable");
      const manifest = await manifestResponse.json();
      const expected = manifest.scenarios?.[key]?.artifacts;
      if (!expected) throw new Error(`fixture manifest has no ${key} scenario`);
      const [certificate, verification, request] = await Promise.all([
        fetchJsonWithDigest(`${base}-certificate.json`, expected.certificate),
        fetchJsonWithDigest(`${base}-verification.json`, expected.verification),
        fetchJsonWithDigest(`${base}-request.json`, expected.request),
      ]);
      data = { certificate, verification, request, manifest };
      cache.set(key, data);
    }
    if (!document.querySelector(`[data-zr-state='${key}'].active`)) return;
    const { certificate, verification, manifest } = data;
    const proofDigest = certificate.reasoning?.proof?.digest;
    const disproofDigest = certificate.reasoning?.disproof?.digest;
    const evidenceDigest = proofDigest || disproofDigest || verification.reasoning_result_digest;
    const issue = certificate.issues?.[0];
    const conflict = certificate.reasoning?.conflict;
    const values = {
      "[data-zr-label]": scenario.label,
      "[data-zr-verdict]": scenario.verdict,
      "[data-zr-title]": scenario.title,
      "[data-zr-detail]": scenario.detail,
      "[data-zr-consequence]": scenario.consequence,
      "[data-zr-result]": certificate.status,
      "[data-zr-exit]": scenario.exit,
      "[data-zr-foot]": verification.status === "verified" ? `Certificate verified · ${verification.authorization_status}` : "Verification failed",
      "[data-zr-digest]": shortDigest(certificate.request_digest),
      "[data-zr-source]": `${manifest.generator} · ${verification.status} · fixture bytes match SHA-256 manifest`,
    };
    Object.entries(values).forEach(([selector, value]) => {
      const element = document.querySelector(selector);
      if (element) element.textContent = value;
    });
    const approval = document.querySelector("[data-zr-approval]");
    if (approval) approval.innerHTML = `<i class="${scenario.evidenceTone}"></i>${escapeHtml(scenario.approval)}`;
    const proofLine = conflict ? `proof ${shortDigest(proofDigest)}\ndisproof ${shortDigest(disproofDigest)}` : `${proofDigest ? "proof" : disproofDigest ? "disproof" : "result"} ${shortDigest(evidenceDigest)}`;
    const issueLine = issue ? `\n${issue.code}: ${issue.atom ? `${issue.atom.predicate}(${issue.atom.arguments.join(", ")})` : issue.message}` : "";
    const command = document.querySelector("[data-zr-command]");
    if (command) command.innerHTML = `<em>$</em> reason authorize data/reason/${key}-request.json\n\n<span>${escapeHtml(scenario.label)}</span>  ${escapeHtml(certificate.action.id)}\n            ${escapeHtml(certificate.action.tool)}(${escapeHtml(Object.values(certificate.action.arguments).join(", "))})\n            ${escapeHtml(proofLine)}${escapeHtml(issueLine)}\n\n<small>Exit ${scenario.exit} · certificate independently ${escapeHtml(verification.status)}</small>`;
    const certificateView = document.querySelector("[data-zr-json]");
    if (certificateView) certificateView.textContent = JSON.stringify({
      schema: certificate.schema,
      status: certificate.status,
      action: certificate.action,
      request_digest: certificate.request_digest,
      reasoning: {
        status: certificate.reasoning.status,
        program_digest: certificate.reasoning.program_digest,
        proof_digest: proofDigest || null,
        disproof_digest: disproofDigest || null,
      },
      verification,
    }, null, 2);
    const links = {
      "[data-zr-certificate-link]": `/reason/data/reason/${key}-certificate.json`,
      "[data-zr-request-link]": `/reason/data/reason/${key}-request.json`,
      "[data-zr-verification-link]": `/reason/data/reason/${key}-verification.json`,
    };
    Object.entries(links).forEach(([selector, href]) => document.querySelector(selector)?.setAttribute("href", href));
  } catch (error) {
    const source = document.querySelector("[data-zr-source]");
    if (source) source.textContent = `Could not load certificate: ${error.message}`;
  }
}

app.innerHTML = page();
document.querySelectorAll("[data-zr-scroll]").forEach(button => button.addEventListener("click", () => document.getElementById(button.dataset.zrScroll)?.scrollIntoView({ behavior: "smooth" })));
document.querySelectorAll("[data-zr-state]").forEach(button => button.addEventListener("click", () => loadScenario(button.dataset.zrState)));
loadScenario("authorized");
