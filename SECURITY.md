# Security

Voyager Repo points an agent at *untrusted* repositories, so its whole design is
defensive.

## No execution of target code

`scout` is **read-only**: it walks files and runs `git` (read-only) — it never
runs the repository's own code. Installing, building, testing, or running are
**withheld** by default and must be explicitly consented (`--allow-install`,
`--allow-exec`, `--allow-clone`). Even when execution is consented, it belongs in
Voyager's hardened rootless container — never on the host.

## Everything from the target is untrusted

README text, manifest descriptions, commit messages, and the Repotector ledger
are **owner-controlled**. Each is injection-stripped (via `@dir-ai/voyager`'s
`stripInjection`) and returned as `FramedText` with a count of payloads removed,
so a hostile repo cannot smuggle instructions into your model through a "brief".

## Bounded, symlink-safe traversal

The walk is breadth-first and bounded (`maxFiles`), skips heavy/noise dirs, and
**never follows symlinks** — a repo cannot make Voyager Repo traverse out of its
own tree into the host filesystem. File reads are byte-capped.

## Fail-closed, honest exit codes

- `0` — oriented, no HIGH-risk finding.
- `1` — oriented, but at least one HIGH-risk finding (install hook, committed
  secret, a dependency Voyager rejected).
- `2` — tool error (path missing, etc.): "could not orient", never a false verdict.

## Composition, least privilege

Dependency verdicts are delegated to `@dir-ai/voyager` (OSV-gated, its own closed
egress allowlist). Voyager Repo itself makes no network calls except that delegated
verification, and only when `--check-deps` is set.

## Reporting

Please report vulnerabilities via a private GitHub security advisory rather than a
public issue.
