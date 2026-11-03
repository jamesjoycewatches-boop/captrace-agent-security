# Security boundaries

CapTrace is an offline **simulation and regression-test harness**. It is not an
identity provider, a sandbox, or a production reference monitor. It does not
make an LLM trustworthy and it does not test live services by default.

No prompts, credentials, network requests, or real external tool calls are
required. All timestamps are virtual integers. A successful test means only
that the supplied simulated scenario matches its expected effects.

**Do not** substitute the in-memory checks in `Engine` for real enforcement at
a service boundary. Production integrations must validate credentials,
requests, scopes, delegation and revocation atomically in the destination
service, including idempotency and in-flight operation handling.

If you discover a vulnerability in this repository, please avoid publishing
secrets or exploit payloads in a public issue. Contact the repository owner
privately through their GitHub profile before disclosing details.
