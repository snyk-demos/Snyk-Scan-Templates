# Snyk Scan Templates

Four composite GitHub Actions that run Snyk scans and put the results where
people actually look: GitHub code scanning (Security tab plus PR diff
annotations), the run summary, and one sticky PR comment per scan that is
edited in place on every push. Optionally, results are also published to the
Snyk Web UI for tracking over time.

| Action | Runs | Scans | Publishes to Snyk UI via |
|---|---|---|---|
| `sca` | `snyk test` | Open source dependencies | separate `snyk monitor` step |
| `code` | `snyk code test` | Your own code (SAST) | `--report` on the same test |
| `iac` | `snyk iac test` | Terraform, CloudFormation, Kubernetes | `--report` on the same test |
| `container` | `snyk container test` | A built image | separate `snyk container monitor` step |

Every action follows the same shape: install a checksum-verified Snyk CLI,
scan, classify any failure into a cause and a fix, report, upload SARIF, and
gate. The gate **fails closed**: only exit 0 (clean), 3 (nothing to scan),
and, unless `fail-on-findings` is set, 1 (findings) pass. Any other exit
code, including an empty one, fails the check with the classified cause. A
broken scan can never look green.

---

## Setup

**1. Add the token.** Repo or org: Settings → Secrets and variables →
Actions → New repository secret. Name it `SNYK_TOKEN`, paste a Snyk API
token. Use a service account token, not a personal one.

**2. Pick an example and copy it.** Two are provided; the difference is who
owns the Snyk platform side.

```bash
mkdir -p .github/workflows
curl -sL https://raw.githubusercontent.com/YOUR-ORG/snyk-scan-templates/v1/examples/snyk-scans.yml \
  -o .github/workflows/snyk-scans.yml
```

**3. Set your org.** `uses:` cannot take a variable, so this is a find and
replace:

```bash
sed -i 's|YOUR-ORG|your-github-org|g' .github/workflows/snyk-scans.yml
```

**4. Commit and open a PR.** You should see the checks, a comment per scan
on the PR, and alerts under the Security tab.

---

## The two examples

### `examples/snyk-scans.yml` - the full scan setup

Use it when the repo is not imported into Snyk through the SCM integration.

- Pull requests run SCA, Code, and IaC.
- Pushes to the default branch run the same three again. That run is the
  **code scanning baseline**: PR alerts are diffed against it, so PRs are
  only flagged for what they introduce, and it **publishes to the Snyk Web
  UI** (`monitor` for SCA, `--report` for Code and IaC), giving you
  trending, notifications on newly disclosed vulns, and UI-managed ignores.
  Publishing is push-only on purpose: enabling it on PRs would create a
  Snyk project per branch.
- The container job also runs on default-branch pushes: it builds the
  image, scans it, and snapshots it to Snyk with `snyk container monitor`.
- The concurrency rule cancels superseded PR runs but **never cancels a
  default-branch run**, so the baseline and the snapshots always complete.

### `examples/snyk-scans-ci-only.yml` - CI gating only

For repos **already imported into Snyk via the SCM integration**. The
platform side is covered there; running `monitor`/`--report` from CI as well
would create duplicate Snyk projects with diverging ignore state, and
scanning twice bills twice.

- SCA, Code, and IaC run on every push to **any** branch and on every PR,
  with SARIF, PR comments, and the gate. Nothing is published to Snyk.
- The container scan runs **only on pushes or merges to the default
  branch**, because the built image is the one thing the SCM integration
  can never see. Scan and SARIF only; monitor stays off.

Both examples are edit-free beyond `YOUR-ORG`:

- **Dependency install is injectable.** The `sca` action's
  `install-command` input defaults to `auto`, which covers the Open
  Source CLI support matrix: npm, Yarn, pnpm, pip, Poetry, Pipenv,
  setup.py, Ruby, PHP Composer, .NET, Maven, Gradle, sbt, Go, Elixir, and
  Swift/CocoaPods. It installs only where Snyk requires a build and with
  lifecycle scripts disabled (a PR's dependencies must never execute a
  PR's scripts on your runner); if a required tool is missing on the
  runner it fails fast with a warning naming the setup step to add. Pass
  any command to override it, or `skip` to disable:

  ```yaml
  - uses: YOUR-ORG/snyk-scan-templates/sca@v1
    with:
      snyk-token: ${{ secrets.SNYK_TOKEN }}
      install-command: "dotnet restore"   # or "make deps", or "skip"
  ```

  The command carries the same trust as the workflow file it is written in.
  Never build it from untrusted input such as PR titles or branch names.

- **The container job skips itself** when there is no Dockerfile at the
  repo root. Nothing to delete.

- **The image is named after the repo** (lowercased, since Docker requires
  it): `your-org/your-repo:<sha>`. The Snyk project name
  then traces straight back to where the image came from.

---

## Making it block merges

Scans are advisory by default. To block: Settings → Branches → branch
protection rule → Require status checks → add **`Code scanning results`**.

Code scanning only flags alerts the PR *introduces*, so an existing backlog
will not block anyone. This is why the default-branch run matters: it is the
baseline the PR is compared against.

Do not also set `fail-on-findings: "true"`. That is a second, blunter gate
on the same thing.

---

## Inputs

### Shared by all four actions

| Input | Default | What it does |
|---|---|---|
| `snyk-token` | required | Snyk API token. A missing secret is caught in one second with a clear error, not an opaque 401 later. |
| `snyk-org` | `""` | Snyk org slug or UUID. Only needed if the token spans orgs. |
| `severity-threshold` | `high` | `low` \| `medium` \| `high` \| `critical`. Findings below it are ignored. |
| `fail-on-findings` | `"false"` | `"true"` fails this check when findings exist. Leave it and let code scanning block instead, or you gate twice. |
| `upload-sarif` | `"true"` | Send results to GitHub code scanning. Private repos need GitHub Code Security; free on public repos. |
| `pr-comment` | `"true"` | Post/update one sticky comment on the PR, found by marker even on PRs with hundreds of comments. |
| `working-directory` | `.` | Directory to scan. For monorepos. |
| `monitor` | `"false"` | Publish to the Snyk Web UI. SCA and container run a separate `monitor` command; Code and IaC add `--report` to the same test. Enable on default-branch pushes only. |
| `target-reference` | `""` | Branch or version grouping for published snapshots, e.g. `main`. Used only when `monitor` is on. |
| `extra-args` | `""` | Extra Snyk CLI flags, appended verbatim as a flag list. |
| `comment-marker` | `snyk-<scan>` | Identifies the sticky comment and the code scanning category. Change it only when calling the same action twice in one repo. |
| `snyk-cli-version` | `latest` | Pin with a version like `"1.1306.1"`. Pinning is recommended for a gate: `latest` can change behavior under you. |
| `github-token` | `${{ github.token }}` | Token used to read the PR and write the comment. |

### `sca` only

| Input | Default | What it does |
|---|---|---|
| `install-command` | `auto` | Pre-scan dependency resolution. `auto` detects the ecosystem per Snyk's support matrix: npm/Yarn/pnpm, pip/Poetry/Pipenv/setup.py, Ruby, PHP Composer, .NET, Maven, Gradle, sbt, Go, Elixir, Swift/CocoaPods. Lockfile-read ecosystems (Ruby, PHP, Go, Swift) install nothing; Maven gets `mvn install` and .NET gets `dotnet restore` as Snyk requires. `skip` runs nothing; anything else runs verbatim in bash. C/C++ needs `extra-args: "--unmanaged"`; Dart and Rust have no Snyk CLI Open Source support. |

### `iac` only

| Input | Default | What it does |
|---|---|---|
| `detection-depth` | `""` | How many directory levels Snyk IaC descends. Scope it down if the scan reaches too deep. |

### `container` only

| Input | Default | What it does |
|---|---|---|
| `image` | required | The image to scan, e.g. `your-org/your-repo:<sha>`. |
| `dockerfile` | `Dockerfile` | Enables base image upgrade advice. A missing file is a warning, not a failure. |
| `exclude-app-vulns` | `"true"` | Scan OS packages only; the `sca` action already covers application dependencies. |
| `project-name` | `""` | Snyk project name for monitor. Empty defaults to `<org>/<repo>/<image-without-tag>`, collapsing to just the image name when it already matches the repo. The tag is stripped so sha tags do not fragment snapshot history into a project per push. |

### Outputs (all actions)

| Output | Meaning |
|---|---|
| `exit-code` | Snyk CLI exit code: 0 clean, 1 findings, 2 error, 3 nothing to scan. |
| `results-file` | SARIF path, relative to `working-directory`. |

---

## Common changes

Add these under `with:` on any scan.

| Want | Add |
|---|---|
| Only fail on critical | `severity-threshold: critical` |
| Fail the check itself, not via code scanning | `fail-on-findings: "true"` |
| Monorepo, scan a subfolder | `working-directory: services/api` |
| Monorepo, scan every project | `extra-args: "--all-projects"` |
| Custom or no dependency install (SCA) | `install-command: "make deps"` or `"skip"` |
| No PR comment, summary only | `pr-comment: "false"` |
| Skip code scanning upload | `upload-sarif: "false"` |
| Pin the CLI version | `snyk-cli-version: "1.1306.1"` |
| IaC reaching too deep | `detection-depth: "3"` |
| Debug a failing scan | `extra-args: "-d"` |

---

## When a check fails

Failures are classified into a cause and a concrete fix, shown in the error
annotation, the run summary, and the PR comment. The reasons:

| Reason | Meaning | Fix |
|---|---|---|
| `misconfig` | The step itself broke (e.g. `command not found`); Snyk never ran. Any "clean" result is void. | Fix the step script. |
| `unsupported` | Snyk found no supported files at the scanned path. | Check `working-directory` and the language support for that scan type. |
| `auth` | Credentials rejected (401). | Recreate `SNYK_TOKEN` as a service account token with access to the org. |
| `forbidden` | 403: token lacks product access or the org hit a plan limit. | Check org entitlement and token org access. |
| `parse` | IaC hit malformed JSON/YAML, almost always inside `node_modules`. | See the IaC rule below. |
| `network` / `server` | Transient network or Snyk-side failure. | Re-run; check egress to `*.snyk.io` and status.snyk.io. |
| `quota` | The Snyk org is out of tests. Warned even on passing scans, since it is why the next one fails. | Wait for reset or upgrade the plan. |

Two rules worth knowing:

**Never install dependencies in the IaC job.** Snyk IaC walks the whole tree
looking for JSON and YAML, finds deliberately malformed test fixtures inside
`node_modules`, and fails.

**A clean scan writes no SARIF file.** Snyk skips the file when nothing is
found, so the upload is skipped too, and the report renders it as clean.
Alerts from a previous run stay open until a run produces a file again.

---

## What the reports look like

- **SCA / container**: findings are deduplicated (Snyk repeats one vuln per
  dependency path) and grouped per package. The report leads with a "Fix
  first" table of direct dependency bumps ranked by how many vulns each
  clears, then a per-package table with direct/transitive, worst severity,
  vuln IDs linked to the Snyk vuln DB, and the concrete action. Packages
  with no available fix are called out explicitly.
  
- **Code / IaC**: each finding shows its CWE and links to the exact file and
  line at the scanned commit. On PRs the links use the PR head SHA, since
  `GITHUB_SHA` there is a synthetic merge commit that is not browsable.

---

## Notes

- Pin a tag (`@v1`).
- Code scanning upload on private repos requires GitHub Code Security.
  Without it, set `upload-sarif: "false"` and use `fail-on-findings:
  "true"` instead.
- If a repo is already imported into Snyk via the SCM integration, use the
  CI-only example. Running publishing from both places creates duplicate
  Snyk projects and could double the test bill.
- Snapshots are only published from completed scans (exit 0 or 1), so a
  broken scan never becomes the platform's latest state.
