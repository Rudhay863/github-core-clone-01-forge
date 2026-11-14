# github-core-clone-01-forge

A standalone GitHub-compatible git forge — one Node process, its own in-memory
store, no UI, no outside service, no git binary. Built for the make.fun
bounty [github-core-clone-01](https://make.fun/r/xk7vph3j) ("Build a
GitHub-compatible git forge", $500 USDC).

## What it serves (one store, four surfaces)

- **Git smart HTTP** at `/{owner}/{repo}.git` — upload-pack protocol v2
  (advertisement, `ls-refs`, `fetch` with shallow/deepen) and v0 fallback,
  receive-pack v0 with fast-forward enforcement (`non-fast-forward` refusals
  per ref, mixed pushes apply the fast-forwarding refs).
- **REST v3** under `/api/v3` — repos, branches, commits, contents (create /
  read / update / delete with git blob SHAs), labels, issues, comments, pull
  requests, squash merge with conflict detection (405).
- **GraphQL** at `/api/graphql` — viewer, repository, node, `__type`
  introspection, issues/pull-requests connections with cursor pagination,
  and mutations (create/close issue, create/merge pull request, add comment),
  including batched operations.
- **MCP** at `/mcp` — JSON-RPC 2.0 Streamable HTTP, protocol revision
  2026-07-28 (plus `initialize` handshake), six tools: `create_repo`,
  `get_repo`, `create_issue`, `list_issues`, `create_pull_request`,
  `merge_pull_request`.

## Run it

Requires Node 22+ (no dependencies, stdlib only).

```sh
node main.ts
```

The forge binds an ephemeral port (`listen(0)`, never 8080), then:

1. `POST {"port": N}` to `$MAKEFUN_ENV_URL/register`
2. long-polls `GET $MAKEFUN_ENV_URL/done` and exits 0 when it answers
   `{"done": true}`

With no `MAKEFUN_ENV_URL` set it just listens and prints its port (handy for
local testing). Auth for the API surfaces is a Bearer token from
`MAKEFUN_SHOP_TOKEN`; git smart-HTTP endpoints need no auth. Repositories are
created through the REST API only — a push can never invent one.

## Design notes

- Single file, `main.ts` (pure JavaScript syntax, runs under Node type
  stripping), ~2,500 lines, stdlib only (`node:http`, `node:crypto`,
  `node:zlib`).
- In-memory store (Maps); no disk fsync on hot paths. Packs are plain
  objects only (no deltas); incoming packs are parsed including OFS/REF
  deltas. All server-made timestamps are derived from a deterministic
  sequence, never wall-clock time, so the state export is byte-identical
  across runs.
- The viewer is the fixed scenario user `adaiversen`; repositories under any
  other owner answer 404 (never 403).

## Local test results

Graded locally against the kit's sealed suite (env server + sealed scorer,
two runs): **976/1000 and 980/1000** — feature 600/600 (all 120 conformance
checks pass), agent 200/200, perf 176–180/200. The state export was
byte-identical across the two runs. Real `git` CLI clone/push/fetch/shallow
clone/tag push also verified by hand.

## License

MIT — see [LICENSE](LICENSE).
