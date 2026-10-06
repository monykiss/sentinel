# SENTINEL — public surface

**SENTINEL is a runtime control plane for AI agents.** It sits in the request
path between agents and the tools they call, works out which agents can reach
regulated data and by what route, closes those routes reversibly, and reports
its own coverage honestly, including when it might be wrong.

This repository is the **client-side surface** of the product: the Python SDK,
the MCP server and the CLI, with their tests and CI. The control plane itself
(gateway, graph engine, policy engine, audit ledger, Control Room UI) is
proprietary and is not published here. A live walkthrough of the full system is
available on request.

---

## What the product does

Every company now runs agents that hold real credentials. Each grant was
reasonable when it was issued; nobody can say which agents can now reach
regulated data, because the answer is spread across IAM, tool registries, data
classification and — for the grants that are actually *used* — nowhere at all.

SENTINEL answers it from the one position where it is answerable:

1. **It builds its own map** from the traffic it already carries. No cloud
   credentials, no IAM read role, no agent to deploy.
2. **It finds routes, not findings.** `sre-oncall → devops-copilot → ci-deploy
   → deploy_migration → prod-db → borrower-pii`: five hops, each defensible on
   its own, ending in regulated data.
3. **It closes them reversibly, and proves it.** A change that cannot be
   verified is rolled back rather than left in place.
4. **The cut is load-bearing.** A route proved closed is refused in the request
   path, and the refusal names the edge that was revoked.

The design principle running through all of it: **a security number is only
worth having if it gets worse when it should.** An empty graph reports itself as
empty rather than clean, observation never claims complete coverage, a denied
attempt is never counted as a grant, and when a source system contradicts a
recorded remediation the headline changes from a percentage to *"3 CONTESTED
REMEDIATIONS"*.

[`docs/demo-transcript.txt`](docs/demo-transcript.txt) is an unedited run of the
eight-act product demo against the real application (fictional tenant): it
asserts 30 invariants in about half a second.

## What is in this repository

| Path | What it is |
|---|---|
| [`sdk/sentinel_sdk/`](sdk/sentinel_sdk) | Python SDK: async and sync clients, plus LangChain, OpenAI function-calling and CrewAI integrations that gate every tool call |
| [`sentinel_mcp/`](sentinel_mcp) | MCP server that lets an AI assistant ask SENTINEL what it may do, and read posture, coverage and findings |
| [`sentinel_cli/`](sentinel_cli) | Terminal client |
| [`tests/`](tests) | Unit, behaviour and contract tests for all three |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Lint, format, typecheck and test on Python 3.11–3.13, dependency audit, secret scan |

## Engineering decisions worth looking at

**The MCP server is a client, not a back door.** It would be simpler to import
the gateway's handlers and call them in-process. That would also bypass every
control that lives in the request path: route access levels, per-tenant rate
limits, tenant resolution and the audit ledger entry. So every tool is an HTTP
call carrying a bearer token, and
[`tests/contracts/test_mcp_does_not_bypass_the_gateway.py`](tests/contracts/test_mcp_does_not_bypass_the_gateway.py)
enforces that structurally by parsing the package's imports, rather than
trusting a convention.

**A model can ask questions, not take actions.** The MCP tools expose reads and
the *decision* endpoint, never tenant isolation, key revocation or policy
activation. Remediation planning is pinned to `dry_run` and takes no arguments,
so no prompt can turn "plan the cut" into "make the cut". The same contract test
asserts this.

**"You may not" is never confused with "I could not ask".** A refusal and an
outage are both non-answers to "may I run this tool", and they call for opposite
behaviour. The client keeps the status code, the server renders them
differently, and neither ever renders as permission
([`tests/mcp/`](tests/mcp)).

**The SDK fails closed.** Anything other than an explicit `allowed`, whether a
denial, a step-up requirement, an unrecognised status, a 4xx/5xx or a proxy's
HTML error page, stops the tool. Every argument the tool will receive is shown
to the guard, positional ones included. The CLI stores its credential with mode
`600` and takes it from the environment, never from shell history.

## About the full system

The private codebase is a FastAPI control plane with a graph engine, a signed
policy engine, an append-only hash-chained audit ledger, deterministic replay and
a Next.js Control Room: roughly 46k lines of Python and 12k of TypeScript, with
3,600+ test functions. Its invariants are numbered, documented where they are
owned, and asserted by contract tests covering, among others, cross-tenant
isolation, ledger immutability, evidence signing, and that declared route access
is actually enforced.

## Running the checks

```bash
uv venv && uv pip install -e '.[mcp,cli,dev]'
ruff check . && ruff format --check . && mypy && pytest
```

The SDK and CLI talk to a SENTINEL gateway; configure one with
`SENTINEL_API_KEY=<key> sentinel init --gateway <url>`.

---

© 2026 KREDO LLC. All rights reserved. Published for review only; see
[LICENSE](LICENSE).
