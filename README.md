# The Tech Meta: the method

[![check](https://github.com/the-tech-meta/method/actions/workflows/check.yml/badge.svg)](https://github.com/the-tech-meta/method/actions/workflows/check.yml)

[The Tech Meta](https://thetechmeta.com) shows the current meta of tech, the way a competitive game has a meta: what
strong teams adopt, keep and drop. It is read from the public git history of open-source repos, in two leagues: a pro
scene and a ladder.

## What this repo is

The method behind the site: the code that builds the two leagues, scans each repo's history and counts the practices, and
the two panels it was run on for Issue #1. It is not the site's source, and it does not hold the scans. Anyone can make
the scans again with `scan.py`: it needs git, the network and the disk for one clone at a time (see Running it).

| Path | What it is |
|---|---|
| `pipeline/panel.py` | Builds both leagues under one rule |
| `pipeline/scan.py` | Replays each repo's history on a monthly grid and writes one scan per repo |
| `pipeline/fingerprints.py` | The rules that recognise a practice in a file tree, a workflow or a commit |
| `pipeline/api_signals.py` | What only the GitHub API shows: pull requests, bots, security settings |
| `pipeline/analyze.py` | Counts the practices per league and writes every figure the site shows |
| `pipeline/common.py` | Paths, the run date, the monthly grid, the `gh` wrapper |
| `pipeline/tests/` | The tests of the rules, the scan and the panels |
| `data/panel_pro.json`, `data/panel_ladder.json` | The two leagues: 209 and 200 repos, built on 2026-11-22 |
| `data/panel_rule.json` | How they were built: the day, the rule, how many repos each condition removed, the ladder's draw |
| `data/ross_index.json` | Which repos each edition of the ROSS Index links to, with the source and the day it was read |

## How the method works

Follow one figure, the share of a league's repos that have a practice.

**1. The leagues** (`panel.py`, `data/panel_rule.json`). On the day the panels are built, a repo passes when:

1. its owner is an organisation;
2. it is public, not archived, not a fork;
3. it was created before 2025-01-01;
4. it had a push in the last 90 days;
5. it has 200 files or more at the tip of its default branch;
6. it had 30 commits or more, merges left out, in the 90 days before 2025-01-17, the first snapshot;
7. its owner is not a maker of a coding agent, a company one of them bought, or an owner tied to them in another way
   (`LEFT_OUT`, each owner with a fact and a link: 38 owners on 2026-11-22).

The pro scene is every repo of the [ROSS Index](https://runacap.com/ross-index/) (any of its 30 editions from Q2 2020 to
Q3 2026, read on 2026-11-22) that passes. The ladder is 200 repos drawn at random among the repos that pass and have 50
stars or more, the pro scene left out: the creation days from 2007-10-29 to 2024-12-31 are put in an order drawn with the
seed 20261122 and read one after the other until 200 or more repos pass (70 days, a pool of 203 on 2026-11-22), then 200
are drawn from them. Both panels were built on 2026-11-22 (`built_on`) and stay fixed between runs, so that a move over
time is a move of the same repos.

**2. The snapshots** (`scan.py`). Each repo is cloned without file contents, back to 90 days before the first snapshot.
Its file tree is read on a monthly grid that ends on the run date: for Issue #1, 23 snapshots from 2025-01-17 to
2026-11-17. A few small files are read too (workflows, agent settings and hooks, instruction files, the package
manager's root files), and the commits of the 90 days behind each snapshot are read for agent signatures. Author
names and addresses are tested in memory and never written out. The clone is deleted once scanned.

**3. The rules** (`fingerprints.py`). A practice is a rule on file paths, workflow text, commit signatures or bot
accounts. No language model reads anything. A trace under templates, examples, fixtures, vendored or built code is
material a project ships to others, not its own setup, and does not count.

**4. The API** (`api_signals.py`). Seven calls per repo: the latest 100 pull requests, review comments and pull request
comments give the agents that open pull requests and the bots that review them; four more read the security settings
anyone can read on a public repo. These have no history: they are read on the day the API is asked, which each file
carries.

**5. The count** (`analyze.py`). Every practice is a yes or no question asked of a repo at a snapshot. Adoption is the
share of a league's repos answering yes, with a Wilson 95% interval; the history, what was kept and what was dropped
compare the same repos over time. It writes `data/meta.json`, every figure the site shows.

## The rules the method keeps

- Public repos only, owned by organisations.
- Aggregate figures only. No person is named, stored or counted: only repos, files and bot accounts.
- Every claim carries one of four evidence levels: observed (teams do it, counted in public repos), reported
  (practitioners say so, not checked), tested (run on a real task, repeatable), benchmarked (a controlled comparison
  with and without). Everything this pipeline produces is observed.
- Adoption is never presented as proof that a practice works.

## What the method cannot see

- A practice that leaves nothing in a repo: an agent used with no file committed, no signature and no bot account;
  settings kept in a tool, on a developer's machine, or in GitHub settings only a repo's admins can read.
- Tools do not leave the same traces, so a count per tool is a lower bound, not a ranking.
- CI systems other than GitHub Actions, and a check behind a task with a plain name: those figures are floors.
- Whether an instruction file is followed or helps, and how good a test is.
- Both leagues are repos alive today: the past shown is the past of today's repos, not of every repo alive then.
- A file that moves to a place no rule covers counts as gone.

## Running it

You need Python 3.9 (the version the code and CI target), git, and the [GitHub CLI](https://cli.github.com/) signed in
(`gh auth login`): `panel.py` and `api_signals.py` call the API through it. The pipeline uses the standard library only.
Run every command from the repo's root.

```sh
export METATECH_AS_OF=2026-11-17                # the run date, the last snapshot of the grid (Issue #1); today if unset
export METATECH_CLONES=/path/to/scratch/clones  # where clones go, each deleted once scanned

# Optional: build both leagues again for a day. It reads GitHub and rewrites the three panel files.
python3 -I pipeline/panel.py rule --on 2026-11-22

python3 -I pipeline/scan.py data/panel_pro.json --jobs 3      # -> data/scan/<owner>__<repo>.json
python3 -I pipeline/scan.py data/panel_ladder.json --jobs 3
# Without METATECH_AS_OF: an API file is stamped with the day it is read.
env -u METATECH_AS_OF python3 -I pipeline/api_signals.py data/panel_pro.json   # -> data/api/<owner>__<repo>.json
env -u METATECH_AS_OF python3 -I pipeline/api_signals.py data/panel_ladder.json
python3 -I pipeline/analyze.py                                # -> data/meta.json
```

`scan.py` and `api_signals.py` skip a repo that already has a file, so a run cut short is resumed by running it again.
`scan.py --only owner/repo` scans one repo; `METATECH_CLONE_TIMEOUT` is a clone's timeout in seconds (900 by default).
GitHub throttles clones when about 8 run at once: keep 3 or 4 jobs in all. As a measure of time: reading both panels
again, 409 repos with 2 jobs per panel side by side, took about 50 minutes on 2026-11-24, each clone deleted as it went.
Building both panels from nothing took about 4,000 API calls on 2026-11-22, the ladder about 75 minutes of them.

To scan your own repos, give `scan.py` and `api_signals.py` a JSON list in the shape of a panel entry: each repo's
`name` (`owner/repo`), `created_at` and `default_branch`. `analyze.py` counts the two league files,
`data/panel_pro.json` and `data/panel_ladder.json`.

The tests:

```sh
python3 -I -m unittest discover -s pipeline/tests -t pipeline/tests
```

Tests that need the scans are skipped when `data/scan/` is not there. CI also runs ruff, pinned in
`requirements-dev.txt`: `ruff check` and `ruff format --check`.

## Licence and errors

The code is under the MIT licence (`LICENSE`). The panel files list public repos with facts GitHub's public API gives
about each on the day of the build: its name, owner type, stars, size, dates, default branch, main language, file count,
commit counts and the commit read, and for the pro scene the ROSS editions that name it. `data/ross_index.json` records
which repos each edition of Runa Capital's ROSS Index links to, with the link to its source; the index itself is Runa
Capital's.

To report an error in the method, a rule that counts wrong or misses, open an issue in this repo:
https://github.com/the-tech-meta/method/issues
