# bitty-storage

Metadata-only candidate bounded storage extension; no database or storage API is implemented. Read [AGENTS](AGENTS.md) and [TODO](TODO.md).

Prerequisite: W-131 / bitty-docs CTX-0267 accepted (commit 21d63dc); W-137 plugin contract accepted (bitty-plugins-docs PR #138, commit 002c7ce). Separate transcript, command history, session snapshots and plugin KV. Terminal Truth remains volatile; capture is opt-in and secret-minimizing.

CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 maps to Issues #4 -> #3 -> #2 -> #1. CTX-0001 (bootstrap) is complete: metadata gates, independent review, first publication, redacted CarryCtx snapshot and branch protection are recorded. CTX-0002 (contract readiness) is accepted on the W-131/W-137 acceptances plus recorded privacy review; CTX-0003 implementation is authorized.
