# ADS external evaluator

This public repository holds an action that can review only pull requests for
`curlie755/agentic-development-harness`. The Harness must consume it by a full
commit SHA from a trusted `pull_request_target` workflow. A mutable tag or branch
is not an admissible reference.

The action:

- reads pull-request metadata, trees and blobs with GitHub REST;
- rejects binary, truncated, executable-unsupported, oversized or stale material;
- returns source text only to trusted Harness main source, which invokes its caller-installed, integrity-verified Claude binary with tools disabled;
- never checks out, imports, shells, or otherwise executes Harness candidate code;
- never receives Claude OAuth or dedicated-App credentials; and
- returns strict material only to the trusted caller, which alone invokes Claude and posts the distinct `ads/external-bootstrap-review` context through the Harness’s dedicated statuses App.

It owns no OAuth token, App token or key. The Harness supplies its existing
main-only Claude credential only to its own checked-out trusted `main` source;
its separate trusted publisher keeps the dedicated-App key in a different environment.
