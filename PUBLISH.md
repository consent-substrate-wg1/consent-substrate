# PUBLISH.md — go-live runbook

Every command below was executed and verified green in the build sandbox
before this file was written. Follow in order; nothing needs to be invented.

## 0. Prerequisites

- A GitHub account (a fresh org is ideal: e.g. `consent-substrate-wg`).
- Git installed locally. GitHub CLI (`gh`) optional but recommended.

## 1. Create the repo

Web UI: github.com/new → name `consent-substrate` → **do not** initialize
with README/LICENSE (they ship here) → create.

With `gh`:

```bash
gh repo create consent-substrate --public --source=. --remote=origin --push
```

Before the first push, replace every `CONSENT_SUBSTRATE_GH_ORG` placeholder
in `.zenodo.json` and `CITATION.cff` with your real org/user name.

## 2. Push

### 2a. Termux path (phone-first, ~10 min)

```bash
pkg install git -y
cp /sdcard/Download/consent-substrate-repo.zip ~
cd ~ && unzip consent-substrate-repo.zip && cd consent-substrate

# replace the org placeholder in all three files at once:
sed -i 's/CONSENT_SUBSTRATE_GH_ORG/<your-username>/g' \
    CITATION.cff .zenodo.json docs/index.html

git init -b main
git add -A
git status                     # confirm NO keys, NO manifests, NO audit logs
git commit -m "consent-substrate v1.1.0: gate, manifest tool, canary, paper"
git remote add origin https://github.com/<your-username>/consent-substrate.git
git push -u origin main
```

Auth on HTTPS push: GitHub needs a **Personal Access Token**, not your
password — github.com → Settings → Developer settings → Personal access
tokens (classic) → generate with `repo` scope → paste it as the password.
Cache it: `git config --global credential.helper store`.

### 2b. Desktop path

```bash
cd consent-substrate
git init -b main
git add -A
git status                     # confirm NO keys, NO signed manifests, NO audit logs
git commit -m "consent-substrate v1.1.0: gate, manifest tool, canary, paper"
git remote add origin git@github.com:<org>/consent-substrate.git
git push -u origin main
```

The CI badge appears on the first run (Actions tab). Green across the
3.9–3.13 matrix is the first credibility claim this repo makes.

## 3. GitHub Pages (paper landing)

`docs/index.html` ships in this repo — a self-contained landing page (no
build step, zero dependencies) linking the preprint and the source.

Settings → Pages → Deploy from a branch → `main`, folder `/docs` → Save.
The site appears at `https://<org>.github.io/consent-substrate/` within a
few minutes. Before pushing, replace the `CONSENT_SUBSTRATE_GH_ORG`
placeholder in `docs/index.html` (GitHub link in the CTA row) along with
the ones in `.zenodo.json` and `CITATION.cff`.

## 4. Zenodo DOI

1. zenodo.org → log in with GitHub → Account → **GitHub** → find
   `consent-substrate` → flip **On**.
2. Zenodo reads `.zenodo.json` for metadata (title, creators, keywords).
3. Cut the release:

```bash
git tag -a v1.1.0 -m "v1.1.0: 38-case canary corpus, gate 21/21, schema-verified CI"
git push origin v1.1.0
```

4. GitHub → Releases → Draft new release → choose tag `v1.1.0` → attach
   `paper/detected-or-proven-preprint.pdf` as a release artifact → publish.
5. Zenodo mints the DOI within minutes. Put the DOI badge + DOI string into
   README.md and CITATION.cff, commit, push (this is the one permitted
   "README-only" commit).

## 5. Order of operations (why it matters)

repo live → CI green → tag v1.1.0 → DOI minted → THEN announce. The paper
references the repo; the repo mints the DOI; the announcement links both.
Announcing before the DOI exists wastes the one chance at a clean launch.

## 6. Announcement (suggested shape)

> We made an LLM agent prove it wasn't compromised — with no telemetry
> beyond a hash chain. Detection primitive replaced: not "does this action
> look bad?" but "was it authorized by a signed manifest / did it touch a
> signed witness?" Paper: <DOI>. Repo: <URL>. The full 38-case replay
> reproduces on one command with zero network access.

Post where the field actually reads: HN "Show HN", LinkedIn, and the OWASP
GenAI security channel. The digest-pair reproducibility exhibit
(`f9181d99…` for the v1.0.0 corpus) is the hook — nobody else in this
market can say "run it and you will get my exact chain digest."
