# ADS external evaluator

This public repository holds an action that can review only pull requests for
`curlie755/agentic-development-harness`. The Harness must consume it by a full
commit SHA from a trusted `pull_request_target` workflow. A mutable tag or branch
is not an admissible reference.

The action:

- reads pull-request metadata, trees and blobs with GitHub REST;
- rejects binary, truncated, executable-unsupported, oversized or stale material;
- gives source text to a caller-installed, integrity-verified Claude binary with tools disabled;
- never checks out, imports, shells, or otherwise executes Harness candidate code;
- removes GitHub and dedicated-App credentials from the Claude child environment; and
- posts the distinct `ads/external-bootstrap-review` context only through the Harness’s dedicated statuses App.

It owns no token or key. The Harness supplies its existing main-only environment
credentials only to an immutable SHA it has independently admitted.
