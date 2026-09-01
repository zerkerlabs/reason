# Reason authorization JSON Schemas

These Draft 2020-12 schemas describe the JSON wire shape of Reason's stable action-authorization and organization-policy values:

- `zerker.reason.action.v1.schema.json`
- `zerker.reason.authorization.v1.schema.json`
- `zerker.reason.authorization-bundle.v1.schema.json`
- `zerker.reason.authorization-verification.v1.schema.json`
- `zerker.reason.policy-source-manifest.v1.schema.json`
- `zerker.reason.policy-template.v1.schema.json`
- `zerker.reason.policy-bundle.v1.schema.json`
- `zerker.reason.policy-source-verification.v1.schema.json`
- `zerker.reason.policy-authorization-input.v1.schema.json`
- `zerker.reason.policy-authorization.v1.schema.json`
- `zerker.reason.policy-authorization-verification-input.v1.schema.json`
- `zerker.reason.error.v1.schema.json`
- `zerker.reason.release-authorization.v1.schema.json`
- `zerker.reason.release-init.v1.schema.json`

Keep `zerker.reason.contracts.v1.schema.json` beside the entry schema when validating so its relative `$ref` resolves. The entry schema's title is the corresponding wire-level `schema` value; the filename and `$id` identify the JSON Schema document.

JSON Schema validates structure, required members, closed typed objects, status vocabularies, digest/timestamp encoding, and the portable path restrictions expressible as JSON patterns. It does **not** establish that evidence is true, enforce UTF-8 byte-length or Unicode-normalization rules, recompute digests, replay proofs, map a status correctly, or authorize an action. Source-manifest inclusion commits exact bytes and review metadata only; it does not prove that a model read or understood prose, or that prose is symbolic truth. Use the corresponding Reason semantic validator and verifier at an enforcement boundary.

Keys and values inside declared application maps such as `mission.constraints` and `action.arguments` remain application-defined. Duplicate JSON object members cannot be represented by a parsed JSON value; the Reason CLI separately rejects them before typed parsing. Organization-policy parsing also requires each JSON number token to already match Reason's deterministic rendering so a lossy floating-point spelling cannot change an authorization commitment. JSON Schema validators see only the parsed numeric value and cannot enforce that lexical rule.
