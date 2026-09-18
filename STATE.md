---
status: active
world: business
domain: agentic-development
verified_on: 2026-09-18
next_review: before the first harness workflow pin
---

# ADS external evaluator

- **What this is:** an externally hosted, immutable-SHA GitHub Action that reviews Agentic Development Harness pull requests as source data only.
- **Current state:** initial source implementation in progress; no target workflow pin or required status is live.
- **Next decision:** admit the exact first commit only after deterministic controls and an independent Claude review, then land the small trusted harness caller.
- **Blockers:** none currently; all target credentials remain in target-repository main-only environments and are never stored here.
- **Links:** target `curlie755/agentic-development-harness`; bootstrap boundary `~/AI/.scratch/ADS-CROSS-VENDOR-BOOTSTRAP-BOUNDARY-20260917.md`.
