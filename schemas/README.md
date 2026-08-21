# Reason authorization JSON Schemas

These Draft 2020-12 schemas describe the JSON wire shape of Reason's stable action-authorization values:

- `zerker.reason.action.v1.schema.json`
- `zerker.reason.authorization.v1.schema.json`
- `zerker.reason.authorization-bundle.v1.schema.json`
- `zerker.reason.authorization-verification.v1.schema.json`
- `zerker.reason.error.v1.schema.json`

Keep `zerker.reason.contracts.v1.schema.json` beside the entry schema when validating so its relative `$ref` resolves. The entry schema's title is the corresponding wire-level `schema` value; the filename and `$id` identify the JSON Schema document.

JSON Schema validates structure, required members, closed typed objects, status vocabularies, and digest/timestamp encoding. It does **not** establish that evidence is true, recompute digests, replay proofs, map a status correctly, or authorize an action. Use `reason verify-authorization-bundle ... --require-authorized` at an enforcement boundary.

Keys and values inside declared application maps such as `mission.constraints` and `action.arguments` remain application-defined. Duplicate JSON object members cannot be represented by a parsed JSON value; the Reason CLI separately rejects them before typed parsing.
