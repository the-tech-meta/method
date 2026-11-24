"""Shared helpers for the Tech Meta pipeline: paths, the snapshot grid, GitHub API access, JSON files.

Every other module imports from here. Not run on its own.

Two environment variables change what it sets:
  METATECH_AS_OF    the day of the last snapshot (YYYY-MM-DD); today by default
  METATECH_CLONES   where scan.py clones repos; .cache/clones under the repo root by default

gh() calls GitHub through the gh CLI, which must be installed and logged in."""

import datetime as dt
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
# Clones are a throwaway cache (each one is deleted once scanned); point this at a scratch disk.
CLONES = Path(os.environ.get("METATECH_CLONES", ROOT / ".cache" / "clones"))

AS_OF = dt.date.fromisoformat(os.environ.get("METATECH_AS_OF", dt.date.today().isoformat()))
# The issue the page is: its number, and the day it is published under, whose month names it on the page
# ("December 2026"). The issue's date is not the day its data were read: that is AS_OF, the day of the last snapshot,
# which the page gives where it dates a figure. No sentence dates the data by the issue, since the data are read a few
# days before it.
ISSUE_N = 1
ISSUE_DATE = dt.date(2026, 12, 1)
# What git sets for a hook to say which repo it runs in. A git command started with these in its environment acts on
# that repo whatever folder it is given: the scan and the checks drop them, so that a test run from a hook cannot commit
# to the repo being pushed.
HOOK_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_PREFIX",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
)
FIRST_SNAPSHOT = dt.date(2025, 1, 1)
ACTIVE_DAYS = 90
# The window behind each snapshot in which a repo's agent-signed commits are counted (scan.py; the scans call the count
# `commits90`, a name kept so that the stored scans still read), and how many of the latest pull requests or comments
# are read for a repo's agents and bots (api_signals.py; GitHub gives 100 at most per call). The page's sentences,
# written by analyze.py, give both.
COMMIT_DAYS = 90
LATEST_ITEMS = 100


def snapshot_dates(as_of=AS_OF, first=FIRST_SNAPSHOT):
    """Monthly grid ending on `as_of`, same day of month (clamped to 28)."""
    day = min(as_of.day, 28)
    out, y, m = [], as_of.year, as_of.month
    while dt.date(y, m, day) >= first:
        out.append(dt.date(y, m, day))
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return out[::-1]


def end_of_day_ts(d):
    return int(dt.datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=dt.timezone.utc).timestamp())


# History is fetched from where the first snapshot's window starts, COMMIT_DAYS days before its end of day, so that
# every snapshot's commits are counted over a full window (2024-10-19T23:59:59Z when the last snapshot is 2026-11-17).
# It is an instant in UTC: git reads a bare date as that day at the time the command runs, in local time, which can
# leave out the first hours of a day. A scan stores the cut it was made with (`since`). An older scan stores none: it
# was cut at OLD_SINCE, a bare date a little before the first snapshot, which leaves the windows of the first two
# snapshots short (47 and 78 of their 90 days on the grid of 2026-11-17).
SHALLOW_SINCE = dt.datetime.fromtimestamp(
    end_of_day_ts(snapshot_dates()[0]) - COMMIT_DAYS * 86400, dt.timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")
OLD_SINCE = "2024-12-01"


def gh(path, params=None, retries=5, jq=None, graphql=False, missing=("404", "410", "451")):
    """GET a GitHub REST endpoint through the gh CLI. Returns None on the HTTP codes of `missing` (404/410/451).
    `jq` filters the answer inside gh, so that a large one (a recursive tree) is not held whole. `graphql` sends `params` as the
    variables of the GraphQL query given as `path`. A tree asks for None on 409 too: GitHub's answer for an empty repository."""
    if graphql:
        cmd = ["gh", "api", "graphql", "-f", "query=" + path]
        for k, v in (params or {}).items():
            cmd += ["-F" if isinstance(v, int) else "-f", "%s=%s" % (k, v)]
    else:
        cmd = ["gh", "api", "-X", "GET", path]
        for k, v in (params or {}).items():
            cmd += ["-f", "%s=%s" % (k, v)]
    if jq:
        cmd += ["--jq", jq]
    for attempt in range(retries):
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0:
            return json.loads(p.stdout)
        err = (p.stderr + p.stdout).lower()
        if any("http " + code in err for code in missing):
            return None
        # Rate limits (primary or secondary) clear on their own: back off, then retry.
        time.sleep(60 * (attempt + 1) if "rate limit" in err else 5)
    raise RuntimeError("gh api %s failed: %s" % (path, p.stderr.strip()[:300]))


def slug(name):
    return name.replace("/", "__")


def read_json(path):
    with open(path) as f:
        return json.load(f)


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    tmp.replace(path)
