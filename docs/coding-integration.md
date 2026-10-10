# Evidence and isolated coding integration

This first integration slice connects native Flame Sword reports to a bounded
MCP interface and the Mithril Code selected-source refactor contract. It does
not install a Desktop plugin, provide a Desktop repair screen, dispatch native
scans from MCP, or convert this Python application into Mithril.

## Implemented flow

1. Native scan snapshots are committed to a profile-bound SQLite store after
   each completed module and at termination. Completed reports survive restart.
   Interrupted jobs become `outcome_unknown`; startup never repeats a scan.
2. `flame.evidence/v1` projects the actual scanner sections, content hashes,
   collection states, and coverage gaps. Missing results remain unknown.
   Known credential fields and email enumeration are excluded from AI context.
   This bounded projection is not a general secret detector: operators must
   still review selected source and observations before sending them.
3. A deterministic assessment currently evaluates only measured response
   header presence. A missing `X-Content-Type-Options` is a policy violation,
   not a verified exploit. Imported measurements retain caller provenance.
4. An explicit Code proposal sends only the selected source and declared edit
   paths to `https://code.mithril.fund/api/refactors`. It uses the configured
   Mithril credential and a caller-persisted UUID request ID. The result remains
   unverified and is never applied to the checkout or executed by MCP.
5. A separately qualified owner verifier compares baseline and candidate
   snapshots in Docker. The controlled qualification preserves route contracts
   and retests the header. A passing receipt applies only to those contracts.

AI analysis of reports uses `api.mithril.fund`; Code proposals use the Code
service. These are separate requests. Proposals do not update CodeGraph or
persist `.mith` artifacts yet.

## CLI and MCP

```sh
.venv/bin/python scripts/flame.py status
.venv/bin/python scripts/flame.py import < report.json
.venv/bin/python scripts/flame.py evidence --assessment-id UUID
.venv/bin/python scripts/flame.py assess --assessment-id UUID
.venv/bin/python scripts/flame.py propose --request-id PERSISTED_UUID < task.json
.venv/bin/python scripts/flame.py propose --request-id SAME_UUID --lookup-only < task.json
.venv/bin/python scripts/flame.py mcp
```

The MCP stdio server exposes `flame_runtime_status`, `flame_evidence_read`,
`flame_assess`, and `flame_code_propose`. There is no scan, shell, candidate
execution, source-write, or deployment tool. The advertised proposal operation
is an explicit inference operation; the consumer must obtain operator intent
before selecting it. Persist its UUID before making the request. An unknown
outcome must be reconciled using the same task and ID with `lookup_only`,
rather than submitted as a new inference request. No automatic retry occurs.

Native consumers should launch the executable with explicit owner configuration:

```json
{
  "command": "/ABSOLUTE/flame-sword/.venv/bin/python",
  "args": ["/ABSOLUTE/flame-sword/scripts/flame.py", "mcp"],
  "env": {
    "FLAME_PROFILE": "desktop-owner",
    "FLAME_STATE_DIR": "/PRIVATE/desktop-owner/flame-state",
    "FLAME_CONFIG_FILE": "/PRIVATE/desktop-owner/flame.env",
    "HERMES_HOME": "/PRIVATE/desktop-owner/hermes",
    "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
  }
}
```

The owner's private configuration may contain a scoped `MITHRIL_API_KEY_REF`
1Password reference. It must not contain a shared root-profile reference by
default. When `HERMES_HOME` is selected, the CLI does not load this checkout's
`.env` implicitly. Environment variables take precedence. Keep both the
configuration and state directory private. Profile namespaces constrain reads
through this interface; they do not isolate processes sharing an OS account.

## Independent qualification

The verifier is an existing trusted Mithril Code runner, configured externally
by the owner; its implementation is not vendored into this repository.
Configure these values in private `.env`:

- `FLAME_CODE_VERIFIER`: absolute path to `apps/code/runner/refactor-verify.mjs`.
- `FLAME_CODE_VERIFIER_SHA256`: reviewed verifier file digest.
- `FLAME_CODE_CONTRACT_SHA256`: reviewed companion
  `packages/workspace/src/code-refactor.ts` digest in the same repository.
- `FLAME_VERIFY_IMAGE`: locally built image digest, never an image supplied by
  the model. Node must support importing the companion TypeScript source.

```sh
docker build -t flame-sword-header-verifier:local examples/header-repair
docker image inspect flame-sword-header-verifier:local --format '{{.Id}}'
# Configure the digest and reviewed verifier paths before continuing.
.venv/bin/python scripts/qualify-header-repair.py --control
# Explicitly configured credentials and one hosted inference request:
FLAME_CONFIG_FILE="$PWD/.env" .venv/bin/python scripts/qualify-header-repair.py
```

The `--control` lane uses a deterministic patch and resolves no credential. It
qualifies orchestration and verification, not model output or hosted access.
Both lanes save private task/proposal/plan/receipt artifacts under
`.local/qualification/UUID/`. The original fixture stays unchanged. The Docker
image contains trusted dependencies only. Candidates receive no host secrets,
network access, or original-checkout mount; they run without root privileges,
with read-only root filesystems and bounded resources. Installation occurs only
while the trusted image is prepared, before any model proposal is admitted.

## Remaining Desktop and System One work

Desktop must bind the tools through its selected-profile native adapter, render
evidence and candidate diffs with the canonical shared workspace components,
and keep execution behind the owner-qualified verifier. It must independently
test authorization, profile switching, cancellation, and restart recovery in a
newly built client. Merely registering MCP does not establish Desktop parity.

System One must link selected source to indexed relationships, preserve the
assessment and input identities, and update the differential index only after
an accepted candidate. Python can use this selected-source verification lane;
full Python semantics, automatic conversion to `.mith`, automatic patch
application, CodeGraph updates, and deployment are outside this slice.
