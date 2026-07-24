#!/usr/bin/env bash
# Resolve dependencies before `snyk test`, which scans RESOLVED dependencies,
# not manifests alone.
#
# Env: INSTALL_COMMAND
#   "auto" (default)  detect the ecosystem below and install accordingly
#   "skip"            do nothing (ecosystem needs no install, or the workflow
#                     installed already)
#   anything else     run it verbatim in bash. The command comes from the
#                     workflow author's own file, the same trust level as the
#                     workflow itself. Never feed it from untrusted input
#                     such as PR titles, branch names, or issue bodies.
set -euo pipefail

cmd="${INSTALL_COMMAND:-auto}"

case "$cmd" in
  skip|none)
    echo "Dependency install skipped (install-command: $cmd)."
    exit 0 ;;
  auto)
    ;;
  *)
    echo "Running custom install command from the workflow."
    bash -ec "$cmd"
    exit 0 ;;
esac

need() {  # need <tool> <ecosystem hint> -> 0 if present, else warn and fail
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "::warning::Detected $2 but '$1' is not on the runner. Add a setup" \
         "step before this action or set the install-command input."
    return 1
  fi
}

# ---- JavaScript / TypeScript (npm, Yarn, pnpm) ------------------------------
if   [ -f package-lock.json ]; then
  echo "Detected npm (package-lock.json)."
  npm ci --ignore-scripts || npm install --ignore-scripts
elif [ -f yarn.lock ]; then
  echo "Detected Yarn (yarn.lock)."
  corepack enable
  yarn install --frozen-lockfile --ignore-scripts
elif [ -f pnpm-lock.yaml ]; then
  echo "Detected pnpm (pnpm-lock.yaml)."
  corepack enable
  pnpm install --frozen-lockfile --ignore-scripts
elif [ -f package.json ]; then
  echo "Detected Node without a lockfile (package.json)."
  npm install --ignore-scripts

# ---- Python (Poetry, Pipenv, pip, setup.py) ---------------------------------
elif [ -f poetry.lock ]; then
  echo "Detected Poetry (poetry.lock)."
  pipx install poetry
  poetry install --no-root --no-interaction
elif [ -f Pipfile.lock ] || [ -f Pipfile ]; then
  echo "Detected Pipenv (Pipfile)."
  pipx install pipenv
  pipenv install --deploy
elif [ -f requirements.txt ]; then
  echo "Detected pip (requirements.txt). Install is required so the full" \
       "dependency tree, nested dependencies included, can be tested."
  pip install -r requirements.txt
elif [ -f setup.py ] || [ -f pyproject.toml ]; then
  echo "Detected a Python package (setup.py/pyproject.toml)."
  pip install -e .

# ---- Ruby (Bundler): lockfile is read directly ------------------------------
elif [ -f Gemfile.lock ]; then
  echo "Ruby: Gemfile.lock present; Snyk reads it directly, no install needed."
elif [ -f Gemfile ]; then
  echo "Ruby: no Gemfile.lock; generating it with bundle install."
  need bundle "Ruby (Gemfile)" && bundle install

# ---- PHP (Composer): lockfile is read directly ------------------------------
elif [ -f composer.lock ]; then
  echo "PHP: composer.lock present; Snyk reads it directly, no install needed."
elif [ -f composer.json ]; then
  echo "PHP: no composer.lock; generating it with composer install."
  need composer "PHP (composer.json)" && composer install --no-scripts --no-interaction

# ---- .NET (NuGet): restore produces obj/project.assets.json -----------------
elif ls ./*.sln >/dev/null 2>&1 || ls ./*.csproj >/dev/null 2>&1 \
  || ls ./*.fsproj >/dev/null 2>&1 || ls ./*.vbproj >/dev/null 2>&1 \
  || [ -f packages.config ]; then
  echo "Detected .NET; running dotnet restore to produce project.assets.json."
  need dotnet ".NET" && dotnet restore

# ---- JVM: Maven must be built; Gradle and sbt are invoked by Snyk -----------
elif [ -f pom.xml ]; then
  echo "Detected Maven. Snyk requires the project built before testing."
  need mvn "Maven (pom.xml)" && mvn -q -B -DskipTests install
elif [ -f build.gradle ] || [ -f build.gradle.kts ]; then
  echo "Gradle: no install needed; Snyk invokes Gradle itself during the scan."
elif [ -f build.sbt ]; then
  echo "sbt (Scala): no install needed; Snyk invokes sbt itself during the" \
       "scan. sbt 1.2 and older also need the sbt-dependency-graph plugin."

# ---- Go modules: manifest and lockfile are read directly --------------------
elif [ -f go.mod ]; then
  echo "Go modules: no install needed, Snyk resolves go.mod/go.sum directly."

# ---- Elixir (Hex): dependencies must be fetched -----------------------------
elif [ -f mix.exs ]; then
  echo "Detected Elixir (mix.exs); fetching dependencies."
  need mix "Elixir (mix.exs)" && mix deps.get

# ---- Swift / Objective-C: manifests are read directly -----------------------
elif [ -f Podfile.lock ] || [ -f Package.swift ]; then
  echo "Swift/ObjC: CocoaPods and Swift Package Manager manifests are read" \
       "directly, no install needed."

else
  echo "::notice::No recognised manifest. If this repo has dependencies, set" \
       "the install-command input. C/C++ needs extra-args: --unmanaged; Dart" \
       "and Rust have no Snyk CLI Open Source support. Otherwise Snyk reports" \
       "'nothing to scan' (exit 3), which passes the gate."
fi
