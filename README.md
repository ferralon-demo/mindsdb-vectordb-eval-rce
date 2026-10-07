# MindsDB: `eval()` on query values in vector-database and SharePoint handlers (CVE-2024-45846 to -45851)

Case study of six eval-injection advisories (CWE-94/95) in [mindsdb/mindsdb](https://github.com/mindsdb/mindsdb)
(GitHub now resolves this name to `mindsdb/mindshub`), all fixed by one commit: integration handlers pass
query-supplied strings to Python's builtin `eval`; the upstream fix replaces each call with `ast.literal_eval`.

> **Demo only, not for use.** This repository is a case study built from unmodified snapshots of
> [mindsdb/mindsdb](https://github.com/mindsdb/mindsdb) at two historical commits. It is not a fork and is not maintained. Do not install, deploy, or
> depend on it: the `baseline` branch contains code affected by the advisories below.

**This branch: `main`** holds only this index. The code is on [`baseline`](https://github.com/ferralon-demo/mindsdb-vectordb-eval-rce/tree/baseline) (tag `poe`, vulnerable) and [`fix`](https://github.com/ferralon-demo/mindsdb-vectordb-eval-rce/tree/fix) (tag `pone`, patched).

## Advisories

All six: `mindsdb` < 24.7.4.1 (lower bound varies), CWE-94/CWE-95, "MindsDB Eval Injection vulnerability", fixed by
commit [`11a4db792a`](https://github.com/mindsdb/mindsdb/commit/11a4db792ad36cf704f7307c7602128b17752c80)
([PR #9533](https://github.com/mindsdb/mindsdb/pull/9533), "Replace eval with literal_eval", merged 2024-07-24).

| CVE | GHSA | Query form (per advisory) | `eval` call at `baseline` (upstream `ff120b08f4`) |
|---|---|---|---|
| [CVE-2024-45846](https://nvd.nist.gov/vuln/detail/CVE-2024-45846) | [GHSA-wcjw-3v6p-4v3r](https://github.com/advisories/GHSA-wcjw-3v6p-4v3r) | `SELECT … WHERE`, Weaviate engine | `WeaviateDBHandler.select`, [`mindsdb/integrations/handlers/weaviate_handler/weaviate_handler.py:338`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/weaviate_handler/weaviate_handler.py#L338) |
| [CVE-2024-45847](https://nvd.nist.gov/vuln/detail/CVE-2024-45847) | [GHSA-crmg-rp64-5cm3](https://github.com/advisories/GHSA-crmg-rp64-5cm3) | `UPDATE`, several vector-store engines | `VectorStoreHandler._dispatch_update`, [`mindsdb/integrations/libs/vectordatabase_handler.py:245`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/libs/vectordatabase_handler.py#L245) |
| [CVE-2024-45848](https://nvd.nist.gov/vuln/detail/CVE-2024-45848) | [GHSA-9gq6-6936-885w](https://github.com/advisories/GHSA-9gq6-6936-885w) | `INSERT`, ChromaDB engine | `ChromaDBHandler.insert`, [`mindsdb/integrations/handlers/chromadb_handler/chromadb_handler.py:332`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/chromadb_handler/chromadb_handler.py#L332) |
| [CVE-2024-45849](https://nvd.nist.gov/vuln/detail/CVE-2024-45849) | [GHSA-c85f-pcx6-2ghm](https://github.com/advisories/GHSA-c85f-pcx6-2ghm) | `INSERT` (list creation), SharePoint engine | `SharepointAPI.create_a_list`, [`mindsdb/integrations/handlers/sharepoint_handler/sharepoint_api.py:252`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/sharepoint_handler/sharepoint_api.py#L252) and [`:255`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/sharepoint_handler/sharepoint_api.py#L255) |
| [CVE-2024-45850](https://nvd.nist.gov/vuln/detail/CVE-2024-45850) | [GHSA-v6g6-3cm3-vf6c](https://github.com/advisories/GHSA-v6g6-3cm3-vf6c) | `INSERT` (site column creation), SharePoint engine | `SharepointAPI.create_a_site_column`, [`sharepoint_api.py:413`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/sharepoint_handler/sharepoint_api.py#L413) |
| [CVE-2024-45851](https://nvd.nist.gov/vuln/detail/CVE-2024-45851) | [GHSA-wf9g-c67g-h4ch](https://github.com/advisories/GHSA-wf9g-c67g-h4ch) | `INSERT` (list item creation), SharePoint engine | `SharepointAPI.create_an_item`, [`sharepoint_api.py:577`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/integrations/handlers/sharepoint_handler/sharepoint_api.py#L577) |

## Ingress at `baseline`

The HTTP SQL endpoint: Flask-RESTX namespace `sql` ([`mindsdb/api/http/namespaces/configs/sql.py:3`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/api/http/namespaces/configs/sql.py#L3),
registered at [`mindsdb/api/http/initialize.py:224`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/api/http/initialize.py#L224)); `@ns_conf.route("/query")`
on class `Query` with handler `post` ([`mindsdb/api/http/namespaces/sql.py:22-30`](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/api/http/namespaces/sql.py#L22-L30)).
`post` reads the JSON field `query` ([line 31](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/api/http/namespaces/sql.py#L31)) and calls
`FakeMysqlProxy().process_query(query)` ([line 49](https://github.com/mindsdb/mindsdb/blob/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c/mindsdb/api/http/namespaces/sql.py#L49)).

From `process_query`, a query reaches an integration handler through MindsDB's SQL planner and executor and
handlers loaded per database engine at run time. This README does not assert a specific static call chain from
the ingress to each `eval`; the advisories describe the query forms that reach them. The handlers are only
active when the corresponding integration is installed (per the advisories).

## What the fix changes

At `11a4db792a`, each `eval(...)` above is `ast.literal_eval(...)` on the same statement (lines shift by one
where `import ast` was added): e.g. [`vectordatabase_handler.py:245`](https://github.com/mindsdb/mindsdb/blob/11a4db792ad36cf704f7307c7602128b17752c80/mindsdb/integrations/libs/vectordatabase_handler.py#L245),
[`weaviate_handler.py:339`](https://github.com/mindsdb/mindsdb/blob/11a4db792ad36cf704f7307c7602128b17752c80/mindsdb/integrations/handlers/weaviate_handler/weaviate_handler.py#L339). No builtin `eval` call remains in
the four changed files; the handlers and the ingress are unchanged.

## Provenance

This is not a fork: a fresh repository whose code branches hold upstream source snapshots, with no upstream
history and no upstream remote.

| Branch | Tag | Upstream commit | Date | Snapshot commit | Snapshot tree |
|---|---|---|---|---|---|
| `baseline` | `poe` | [`ff120b08f4`](https://github.com/mindsdb/mindsdb/commit/ff120b08f45a4b15a313f7723ea0f2d8aa4be87c) | 2024-07-23 | `8e6ff4c1ba8fb72eaad7a8e195ef2a20647d491b` | `4f91fdb2b0aaa8bce5464e868c4757c06d4452b1` |
| `fix` | `pone` | [`11a4db792a`](https://github.com/mindsdb/mindsdb/commit/11a4db792ad36cf704f7307c7602128b17752c80) | 2024-07-24 | `4471ebcf4a3507288da6f5a731beaaeaeed6081f` | `2d55a54d85980599cd8f163b17fd5e4c6ede119e` |

Each snapshot commit is the upstream tree at that commit with one change: `.github/workflows/` (9 files) is
removed so that upstream CI does not run here. No other file is added, removed, or edited. The `fix` snapshot's
parent is the `baseline` snapshot, so the diff between the two snapshot commits
([compare](https://github.com/ferralon-demo/mindsdb-vectordb-eval-rce/compare/8e6ff4c1ba8fb72eaad7a8e195ef2a20647d491b...4471ebcf4a3507288da6f5a731beaaeaeed6081f)) is exactly the upstream fix commit's diff. On each code branch, a second
commit replaces upstream's `README.md` with a branch-specific version of this file; upstream's README is in the snapshot commit.

To check a snapshot against upstream from a clone of this repository:

```sh
git fetch https://github.com/mindsdb/mindsdb ff120b08f45a4b15a313f7723ea0f2d8aa4be87c
git diff --stat FETCH_HEAD 8e6ff4c1ba8fb72eaad7a8e195ef2a20647d491b   # lists only .github/workflows/*
```

## Tags

| Tag | Commit | Pins |
|---|---|---|
| `poe` | `870b4f134b33d5f0521b5b4a0a2b987218a74617` | `baseline`: vulnerable snapshot plus this README |
| `pone` | `01a0019d326400da5f369de763542ae43187faf2` | `fix`: patched snapshot plus this README |

## Licence

MindsDB's licensing is mixed and is reproduced unchanged. The root `LICENSE` is kept verbatim, preamble included:
it applies the **Elastic License 2.0** to MindsDB Core and, by default, to any file without a closer licence, and
the **MIT License** to `mindsdb/integrations/`, which carries its own `mindsdb/integrations/LICENSE` (also kept
verbatim). The Elastic License 2.0 is a source-available licence, not an OSI-approved open-source licence. Anyone
who receives a copy of any part of this repository receives these terms with it in `LICENSE`.

**Modification notice (Elastic License 2.0, "Notices"): this is a modified copy of MindsDB.** On 2026-10-07 the
directory `.github/workflows/` (9 files) was removed from both snapshots so that upstream CI does not run here.
That is the only change to MindsDB's files. In addition, this `README.md` replaces upstream's `README.md` in a
separate commit on each branch; upstream's README is unchanged in the snapshot commit. No source file was added,
removed, or edited.
