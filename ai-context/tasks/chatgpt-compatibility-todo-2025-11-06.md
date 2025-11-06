# Compatibility TODO — ChatGPT — 2025-11-06

Scope: Track actions to align the repo with `agent.md` rules. Tests intentionally ignored per request.

Now
- Dynamic version logging
  - Configure build so JAR manifest contains `Implementation-Version=${project.version}`.
  - Update `BurpExtender` to log version via `getPackage().getImplementationVersion()` with a null fallback.

Next
- Montoya dependency scope
  - Set `net.portswigger.burp.extensions:montoya-api` to `<scope>provided</scope>` to avoid bundling.

- Split oversized file(s)
  - `src/main/java/auraditor/suite/ui/ActionsTab.java` (7849 lines) → refactor into smaller modules (<2000 lines) without changing behavior.

Later
- Optional: Dynamic build timestamp
  - Add `Implementation-Build-Time` via Maven and log it (if desired).

- README verification
  - If version display or build instructions change, reflect minimal updates in `README.md`.

Notes
- Confirm all networking continues to use Montoya or passive sources (currently compliant).
- Keep changes focused; do not alter unrelated modules without explicit approval.
