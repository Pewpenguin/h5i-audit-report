# h5i-audit-report

Turn the JSON from `h5i browser audit --json` into a single self-contained HTML report you can archive, attach to CI, or share without installing h5i.

The generated HTML embeds its CSS and JavaScript and does not load remote assets.

The report includes session identity and starting URL; placement, engine, and session lane; ending state and reason; policy digest; evidence availability for each audit source; summary counts; and an ordered event timeline. Requests are labeled Allowed or Denied (with denial reasons when present). The HTML includes simple client-side filters for event type and request decision.

## Install

```bash
cargo install --path .
```

Or build a release binary:

```bash
cargo build --release
```

The binary is then at `target/release/h5i-audit-report`.

## Usage

Audit JSON file → HTML file:

```bash
h5i-audit-report audit.json --out report.html
```

Audit JSON file → stdout:

```bash
h5i-audit-report audit.json > report.html
```

stdin → stdout:

```bash
h5i browser audit --json | h5i-audit-report > report.html
```

stdin → output file:

```bash
h5i browser audit --json | h5i-audit-report --out report.html
```

## Example

Checked-in fixture from a real h5i session audit:

- [examples/audit.json](examples/audit.json)
- [examples/report.html](examples/report.html)

Regenerate the HTML from the fixture:

```bash
h5i-audit-report examples/audit.json --out examples/report.html
```

## Relationship to h5i

This tool only **reads** a session audit object produced by `h5i browser audit --json`. It does not open or modify browser sessions, apply policies, or load or execute anything from the audited page.

The root JSON array from `h5i browser audit --json --no-session` (sessionless helper log) is **not** supported.

### What the report proves

It presents the evidence contained in the supplied h5i session audit: what that JSON records about the session, its sources, and its ordered events.

### What it does not prove

It cannot reconstruct missing, unavailable, or dropped evidence. It does not independently verify the audited page or re-run the session.

## Development

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

## License

MIT. See [LICENSE](LICENSE).
