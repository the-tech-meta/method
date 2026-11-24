"""Build the two leagues under one rule: `panel.py rule --on <day>` writes data/panel_pro.json, data/panel_ladder.json and
data/panel_rule.json (the day of the build, the rule, each league's funnel, the ladder's days and pool).

The rule is one for both leagues and is read on the day the panels are built. A repo passes when: 1. its owner is an
organisation (GitHub's owner type); 2. it is public, not archived, not a fork; 3. it was created before CREATED_BEFORE; 4. it
had a push in the last ACTIVE_DAYS days; 5. it has MIN_FILES files or more at the tip of its default branch; 6. it had
MIN_EARLY_COMMITS commits or more in the EARLY_DAYS days before EARLY_DAY (activity read before agents); 7. its owner is not
in LEFT_OUT (a maker of a coding agent the page counts, a company one of them bought, or an owner tied to them in another
way). The pro scene is every repo of the ROSS Index (data/ross_index.json) that passes; the ladder is LADDER_SIZE repos
drawn at random among the repos that pass and have MIN_STARS stars or more, the pro scene left out. Conditions 5 and 6 are
read through the API (the recursive tree, the commit history), so both panels are rebuilt with no clone.

API answers are cached under data/raw/rule/<day>/, so a second build for the same day makes no call. Needs the gh CLI, logged in.
"""

import argparse
import concurrent.futures
import hashlib
import datetime as dt
import random
import sys
import time
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ACTIVE_DAYS, COMMIT_DAYS, DATA, OLD_SINCE, end_of_day_ts, gh, read_json, write_json

MIN_STARS = 50

# --- The rule: its thresholds, the one source the panels, the build's file and the Method tab read ------------------
OWNER_TYPE = "Organization"  # 1. GitHub's owner type
CREATED_BEFORE = dt.date(2025, 1, 1)  # 3. created before this day
#                                          4. a push in the last ACTIVE_DAYS days (common.py), counted back from the day of the build
MIN_FILES = 200  # 5. files at the tip of the default branch (blobs, links and submodules, as a scan counts)
EARLY_DAY = dt.date(2025, 1, 17)  # 6. the first snapshot of the scans: commits are read in the window behind it,
EARLY_DAYS = COMMIT_DAYS  #    of COMMIT_DAYS days, as a scan's `commits90` is
MIN_EARLY_COMMITS = 30  #    with this many commits or more, merges left out
LADDER_SIZE = 200  # the ladder: this many repos, with MIN_STARS stars or more
RULE_FIRST_DAY = dt.date(
    2007, 10, 29
)  # the ladder's creation days run from GitHub's first repo (its search answers none before)
RULE_SEED = 20261122  # the seed of the ladder's draw under the rule

RULE = {
    "owner_type": OWNER_TYPE,
    "created_before": CREATED_BEFORE.isoformat(),
    "active_days": ACTIVE_DAYS,
    "min_files": MIN_FILES,
    "early_day": EARLY_DAY.isoformat(),
    "early_days": EARLY_DAYS,
    "min_early_commits": MIN_EARLY_COMMITS,
    "min_stars": MIN_STARS,
    "ladder_size": LADDER_SIZE,
}

# The conditions, in the order `fails` tries them and the funnel counts them (the cheap facts first), each with its number.
CONDITIONS = (
    ("organisation", 1, "owned by an organisation"),
    ("public", 2, "public"),
    ("not_archived", 2, "not archived"),
    ("not_fork", 2, "not a fork"),
    ("created", 3, "created before %s" % CREATED_BEFORE.isoformat()),
    ("pushed", 4, "a push in the last %d days" % ACTIVE_DAYS),
    ("not_vendor", 7, "owner not a coding-agent maker or bought by one"),
    ("files", 5, "%d files or more at the tip" % MIN_FILES),
    (
        "early_commits",
        6,
        "%d commits or more in the %d days before %s" % (MIN_EARLY_COMMITS, EARLY_DAYS, EARLY_DAY.isoformat()),
    ),
)
CHEAP = ("organisation", "public", "not_archived", "not_fork", "created", "pushed", "not_vendor")

ROSS = DATA / "ross_index.json"  # which repo was in which edition of the ROSS Index
CACHE = DATA / "raw" / "rule"  # what the API answered, per day of build (data/raw/ is not tracked)
EARLY_PAGES = 30  # commits of the early window read per repo: 3,000 at most, then the count is a floor
LOW_QUOTA = 500  # wait when the REST or GraphQL quota (shared with other jobs on the same token) is under this

# The GitHub owners that stay out of both leagues (condition 7), lowercase. The tie says why: "maker", a maker of a coding agent
# the page counts (`TOOLS` in analyze.py); "bought", a company one of them bought; "named", left out by an editorial decision:
# a maker's parent, former name or former maker, or the maker of an agent the page does not count. Each comes with the tools of
# TOOLS it stands for, a fact and a link anyone can open. The list goes by owner: a vendor's project kept under another
# organisation's name is not caught. The tests fail if a panel repo's owner is here, or if a tool of TOOLS has no owner here.
# The facts were checked on 2026-11-22.
LEFT_OUT = {
    "anthropics": {
        "tools": ["claude"],
        "tie": "maker",
        "fact": "Anthropic's organisation; Claude Code's repo is anthropics/claude-code",
        "link": "https://github.com/anthropics/claude-code",
    },
    "oven-sh": {
        "tools": ["claude"],
        "tie": "bought",
        "fact": "Bun, bought by Anthropic on 2 December 2025",
        "link": "https://www.anthropic.com/news/anthropic-acquires-bun-as-claude-code-reaches-usd1b-milestone",
    },
    "stainless-api": {
        "tools": ["claude"],
        "tie": "bought",
        "fact": 'Stainless: "Today, Anthropic is acquiring Stainless" (Anthropic, 18 May 2026)',
        "link": "https://www.anthropic.com/news/anthropic-acquires-stainless",
    },
    "cursor": {
        "tools": ["cursor"],
        "tie": "maker",
        "fact": "Cursor's organisation (cursor.com); GitHub sends getcursor/cursor to cursor/cursor",
        "link": "https://github.com/cursor/cursor",
    },
    "anysphere": {
        "tools": ["cursor"],
        "tie": "maker",
        "fact": 'Anysphere, the company behind Cursor: "Anysphere acquires Supermaven to beef up Cursor" (TechCrunch)',
        "link": "https://techcrunch.com/2024/11/12/anysphere-acquires-supermaven-to-beef-up-cursor",
    },
    "getcursor": {
        "tools": ["cursor"],
        "tie": "named",
        "fact": "Cursor's former organisation name (GitHub sends getcursor/cursor to cursor/cursor). The "
        "organisation now under that name was created on 2025-06-25, has no public repo and names no company",
        "link": "https://github.com/cursor/cursor",
    },
    "supermaven-inc": {
        "tools": ["cursor"],
        "tie": "bought",
        "fact": 'Supermaven (its Neovim plugin, supermaven-inc/supermaven-nvim, is linked from its post): "Supermaven is '
        'joining Cursor", 12 November 2024; TechCrunch: "Anysphere acquires Supermaven"',
        "link": "https://supermaven.com/blog/cursor-announcement",
    },
    "withgraphite": {
        "tools": ["cursor"],
        "tie": "bought",
        "fact": 'Graphite (graphite.dev): "Graphite has entered into a definitive agreement to be acquired by Cursor", '
        "19 December 2025",
        "link": "https://cursor.com/blog/graphite",
    },
    "openai": {
        "tools": ["codex"],
        "tie": "maker",
        "fact": "OpenAI's organisation; Codex's repo is openai/codex",
        "link": "https://github.com/openai/codex",
    },
    "astral-sh": {
        "tools": ["codex"],
        "tie": "bought",
        "fact": "Astral (uv, Ruff): OpenAI announced on 19 March 2026 that it is buying it; no closing notice found",
        "link": "https://openai.com/index/openai-to-acquire-astral",
    },
    "statsig-io": {
        "tools": ["codex"],
        "tie": "bought",
        "fact": 'Statsig (statsig.com): "we\'re acquiring Statsig" (OpenAI, 2 September 2025), subject to closing conditions',
        "link": "https://openai.com/index/vijaye-raji-to-become-cto-of-applications-with-acquisition-of-statsig/",
    },
    "promptfoo": {
        "tools": ["codex"],
        "tie": "bought",
        "fact": 'Promptfoo (promptfoo.dev): "We\'re acquiring Promptfoo" (OpenAI, 9 March 2026), subject to closing conditions',
        "link": "https://openai.com/index/openai-to-acquire-promptfoo/",
    },
    "github": {
        "tools": ["copilot"],
        "tie": "maker",
        "fact": "GitHub's organisation; GitHub makes GitHub Copilot",
        "link": "https://github.com/features/copilot",
    },
    "cli": {
        "tools": ["copilot"],
        "tie": "maker",
        "fact": 'GitHub CLI: the organisation\'s profile is "GitHub CLI", cli.github.com',
        "link": "https://github.com/cli",
    },
    "actions": {
        "tools": ["copilot"],
        "tie": "maker",
        "fact": "GitHub Actions: the organisation's profile links github.com/features/actions",
        "link": "https://github.com/actions",
    },
    "npm": {
        "tools": ["copilot"],
        "tie": "bought",
        "fact": 'npm: "GitHub has signed an agreement to acquire npm", 16 March 2020',
        "link": "https://github.blog/news-insights/company-news/npm-is-joining-github/",
    },
    "microsoft": {
        "tools": ["copilot"],
        "tie": "named",
        "fact": "GitHub's parent: Microsoft completed its purchase of GitHub on 26 October 2018",
        "link": "https://blogs.microsoft.com/blog/2018/10/26/microsoft-completes-github-acquisition/",
    },
    "microsoftlearning": {
        "tools": ["copilot"],
        "tie": "named",
        "fact": "Microsoft Learning: the organisation's profile links microsoft.com/learning; Microsoft is left out as "
        "GitHub's parent",
        "link": "https://github.com/MicrosoftLearning",
    },
    "dotnet": {
        "tools": ["copilot"],
        "tie": "named",
        "fact": "left out as Microsoft's: \".NET is open source and cross-platform and is maintained by Microsoft and "
        'the .NET community on GitHub", and the page links github.com/dotnet (Microsoft, dotnet.microsoft.com). '
        "The organisation's GitHub profile does not name Microsoft",
        "link": "https://dotnet.microsoft.com/en-us/platform/open-source",
    },
    "google": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": "Google's organisation (opensource.google); Google makes Gemini CLI and Jules",
        "link": "https://github.com/google",
    },
    "google-gemini": {
        "tools": ["gemini"],
        "tie": "maker",
        "fact": "Gemini CLI's repo is google-gemini/gemini-cli",
        "link": "https://github.com/google-gemini/gemini-cli",
    },
    "google-labs-code": {
        "tools": ["jules"],
        "tie": "maker",
        "fact": "Google Labs Code: Jules's GitHub Action is google-labs-code/jules-action",
        "link": "https://github.com/google-labs-code/jules-action",
    },
    "anomalyco": {
        "tools": ["opencode"],
        "tie": "maker",
        "fact": "Anomaly; opencode's repo is anomalyco/opencode",
        "link": "https://github.com/anomalyco/opencode",
    },
    "sst": {
        "tools": ["opencode"],
        "tie": "maker",
        "fact": "Anomaly's former organisation: its profile reads \"We've moved to https://github.com/anomalyco\", and GitHub sends "
        "sst/opencode to anomalyco/opencode",
        "link": "https://github.com/sst",
    },
    "cognitionai": {
        "tools": ["windsurf", "devin"],
        "tie": "maker",
        "fact": 'Cognition, "Makers of Devin" (its profile); it signed to buy Windsurf on 14 July 2025',
        "link": "https://cognition.ai/blog/windsurf",
    },
    "exafunction": {
        "tools": ["windsurf"],
        "tie": "maker",
        "fact": 'Exafunction, Inc., which licensed "Devin Desktop (fka Windsurf)" (Cognition\'s terms); the organisation holds '
        "windsurf.vim and windsurf.nvim",
        "link": "https://cognition.com/legal/platform-terms-of-service",
    },
    "cline": {
        "tools": ["cline"],
        "tie": "maker",
        "fact": "Cline's repo is cline/cline",
        "link": "https://github.com/cline/cline",
    },
    "roocodeinc": {
        "tools": ["cline"],
        "tie": "maker",
        "fact": "Roo Code's repo is RooCodeInc/Roo-Code",
        "link": "https://github.com/RooCodeInc/Roo-Code",
    },
    "kilo-org": {
        "tools": ["cline"],
        "tie": "maker",
        "fact": "Kilo Code's repo is Kilo-Org/kilocode",
        "link": "https://github.com/Kilo-Org/kilocode",
    },
    "kirodotdev": {
        "tools": ["kiro"],
        "tie": "maker",
        "fact": "Kiro's repo is kirodotdev/Kiro",
        "link": "https://github.com/kirodotdev/Kiro",
    },
    "aws": {
        "tools": ["kiro"],
        "tie": "maker",
        "fact": 'Amazon Web Services; Kiro is "Built and run by AWS" (kiro.dev)',
        "link": "https://kiro.dev",
    },
    "aws-samples": {
        "tools": ["kiro"],
        "tie": "maker",
        "fact": 'AWS Samples: the organisation\'s profile names AWS and links amazon.com/aws; Kiro is "Built and run by AWS"',
        "link": "https://github.com/aws-samples",
    },
    "withfig": {
        "tools": ["kiro"],
        "tie": "bought",
        "fact": 'Fig: "Amazon Web Services acquires Fig" (GeekWire, 29 August 2023); its team and company joined AWS',
        "link": "https://www.geekwire.com/2023/amazon-web-services-acquires-fig-a-yc-grad-that-boosts-the-command-line-for-devs/",
    },
    "ampcode": {
        "tools": ["amp"],
        "tie": "maker",
        "fact": 'Amp (ampcode.com), "The frontier coding agent" (its profile)',
        "link": "https://ampcode.com/news/amp-inc",
    },
    "sourcegraph": {
        "tools": ["amp"],
        "tie": "named",
        "fact": 'Amp\'s maker until "Sourcegraph and Amp are becoming two separate companies", 2 December 2025',
        "link": "https://sourcegraph.com/blog/why-sourcegraph-and-amp-are-becoming-independent-companies",
    },
    "zed-industries": {
        "tools": [],
        "tie": "named",
        "fact": "Zed ships an agent the page does not count",
        "link": "https://zed.dev",
    },
    "openhands": {
        "tools": [],
        "tie": "named",
        "fact": "OpenHands makes a coding agent the scan reads (its .openhands folder) and the page does "
        'not count, so its own repo measures its own product. Its README: "Agent Canvas runs the open source '
        'OpenHands agent out-of-the-box"',
        "link": "https://github.com/OpenHands/OpenHands",
    },
    "continuedev": {
        "tools": [],
        "tie": "named",
        "fact": "Continue makes a coding agent the scan reads (its .continue folder) and the page does "
        'not count, so its own repo measures its own product. Its README: "Continue is a coding agent available '
        'as a CLI, VS Code extension, and JetBrains plugin"',
        "link": "https://github.com/continuedev/continue",
    },
}


# --- The rule ----------------------------------------------------------------------------------------------------------------


def fails(facts, on):
    """The conditions of the rule a repo fails on the day `on` (a date), in the order of CONDITIONS; [] when it passes.
    `facts` holds what `repo_facts` and `git_facts` read. Condition 7 reads `owner`, the owner's login as GitHub answers it today,
    not the name as a list types it: a repo renamed or moved under a vendor's organisation is left out. A fact that was not read
    (missing or None) fails its condition.
    A file count from a tree GitHub cut is a floor, and so is a commit count past EARLY_PAGES: a floor at the threshold passes."""
    cutoff = (on - dt.timedelta(days=ACTIVE_DAYS)).isoformat()
    created, pushed, files, early = (facts.get(k) for k in ("created", "pushed", "files", "early_commits"))
    holds = {
        "organisation": facts.get("owner_type") == OWNER_TYPE,
        "public": facts.get("private") is False,
        "not_archived": facts.get("archived") is False,
        "not_fork": facts.get("fork") is False,
        "created": bool(created) and created < CREATED_BEFORE.isoformat(),
        "pushed": bool(pushed) and pushed >= cutoff,
        "not_vendor": bool(facts.get("owner")) and facts["owner"].lower() not in LEFT_OUT,
        "files": files is not None and files >= MIN_FILES,
        "early_commits": early is not None and early >= MIN_EARLY_COMMITS,
    }
    return [c for c, _, _ in CONDITIONS if not holds[c]]


def repo_facts(r):
    """The facts of conditions 1 to 4 and 7, from a REST repo or a search item, which carry the same fields. `name` and `owner` are
    the ones GitHub answers (a REST call follows a rename or a transfer), never the name the call was made with."""
    return {
        "name": r["full_name"],
        "owner": r["owner"]["login"],
        "owner_type": r["owner"]["type"],
        "private": r["private"],
        "archived": r["archived"],
        "fork": r["fork"],
        "created": r["created_at"][:10],
        "pushed": (r.get("pushed_at") or "")[:10] or None,
        "stars": r["stargazers_count"],
        "default_branch": r["default_branch"],
        "size_kb": r["size"],
        "language": r["language"],
    }


EARLY_HI = end_of_day_ts(EARLY_DAY)  # a scan's window behind a snapshot: (hi - EARLY_DAYS days, hi]
EARLY_LO = EARLY_HI - EARLY_DAYS * 86400
SCAN_FROM = int(dt.datetime.fromisoformat(OLD_SINCE).replace(tzinfo=dt.timezone.utc).timestamp())
Q_EARLY = """query($owner:String!, $name:String!, $since:GitTimestamp!, $until:GitTimestamp!%s) {
  repository(owner:$owner, name:$name) { defaultBranchRef { name target { ... on Commit { oid tree { oid }
    history(since:$since, until:$until, first:100%s) { totalCount pageInfo { hasNextPage endCursor }
      nodes { committedDate parents { totalCount } } } } } } } }"""


def stamp(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_ts(iso):
    return int(dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


def git_facts(name):
    """Conditions 5 and 6 through the API, with no clone.
    6: the commits of the default branch's history (every ancestor of its tip, as `git log` walks it, not the first parents only)
    whose commit date falls in (EARLY_LO, EARLY_HI], merges (two parents or more) left out: what scan.read_commits counts as a
    snapshot's `commits90`. GitHub's history answers by the tip of today, so a history rewritten since answers fewer, or none.
    Also kept: `early_scan`, the same count from OLD_SINCE on, the part of the window an older scan (cloned from OLD_SINCE)
    can see, and `early_total`, GitHub's own count of the window, merges included.
    5: the entries of the tip's recursive tree that are not folders (files, links, submodules), as a scan's `git ls-tree -r`."""
    owner, repo = name.split("/", 1)
    since, until = stamp(EARLY_LO + 1), stamp(EARLY_HI)
    counted = scan_part = 0
    after, pages, cut, tip, tree, total = None, 0, False, None, None, None
    while True:
        params = {"owner": owner, "name": repo, "since": since, "until": until}
        if after:
            params["after"] = after
        query = Q_EARLY % ((", $after:String", ", after:$after") if after else ("", ""))
        d = gh(query, params, graphql=True)
        ref = (((d or {}).get("data") or {}).get("repository") or {}).get("defaultBranchRef")
        if not ref or not ref.get("target"):
            break  # an empty repository: no tip, no tree, no commit
        t = ref["target"]
        tip, tree = t["oid"], t["tree"]["oid"]
        h = t["history"]
        total = h["totalCount"]
        for node in h["nodes"]:
            ts = to_ts(node["committedDate"])
            if EARLY_LO < ts <= EARLY_HI and node["parents"]["totalCount"] < 2:
                counted += 1
                scan_part += ts >= SCAN_FROM
        pages += 1
        if not h["pageInfo"]["hasNextPage"]:
            break
        if pages >= EARLY_PAGES:
            cut = True
            break
        after = h["pageInfo"]["endCursor"]
    out = {
        "tip": tip,
        "early_commits": counted if tip else 0,
        "early_scan": scan_part,
        "early_total": total or 0,
        "early_cut": cut,
        "files": 0,
        "files_cut": False,
        "pages": pages + bool(tree),
    }
    if tree:
        t = gh(
            "repos/%s/git/trees/%s" % (name, quote(tree)),
            {"recursive": 1},
            jq='{n: ([.tree[] | select(.type != "tree")] | length), cut: .truncated}',
            missing=("404", "409", "410", "451"),
        )
        if t:
            out["files"], out["files_cut"] = t["n"], bool(t["cut"])
    return out


class Reader:
    """The API's answers for one day of build, cached under data/raw/rule/<day>/, so that a second build that day costs nothing.
    A personal account's repo is never written: its answer is cached as its owner type alone."""

    def __init__(self, on):
        self.on, self.root, self.calls, self.since_check = on, CACHE / on.isoformat(), 0, 0

    def _cached(self, kind, key, fetch, cost=1):
        path = (
            self.root / kind / (hashlib.sha1(key.lower().encode()).hexdigest()[:20] + ".json")
        )  # no name in a file name
        if path.exists():
            return read_json(path)
        self.guard()
        value = fetch()
        self.calls += cost if not isinstance(value, dict) or "pages" not in value else value.pop("pages")
        write_json(path, value)
        return value

    def guard(self):
        """Wait while the quota shared with other jobs on the same token is low: read it every 50 calls."""
        if self.calls - self.since_check < 50:
            return
        self.since_check = self.calls
        while True:
            r = gh("rate_limit")["resources"]
            low = [k for k in ("core", "graphql") if r[k]["remaining"] < LOW_QUOTA]
            if not low:
                return
            wait = max(r[k]["reset"] for k in low) - time.time() + 5
            print("quota low (%s), waiting %d s" % (", ".join(low), wait), flush=True)
            time.sleep(max(wait, 60))

    def repo(self, name):
        """The repo's facts by any name GitHub answers (it follows a rename), or {"missing": True}."""

        def fetch():
            r = gh("repos/" + name)
            if r is None:
                return {"missing": True}
            facts = repo_facts(r)
            return facts if facts["owner_type"] == OWNER_TYPE else {"owner_type": facts["owner_type"]}

        facts: dict = self._cached("repos", name, fetch)
        if (
            "name" in facts and "owner" not in facts
        ):  # a cache written before `owner` was kept: its `name` is GitHub's full_name
            facts["owner"] = facts["name"].split("/")[0]
        return facts

    def git(self, name):
        return self._cached("git", name, lambda: git_facts(name))

    def search_day(self, day, cutoff):
        """The ladder's query for one creation day: the organisations' repos with their facts; the others counted, never named."""

        def fetch():
            q = "stars:>=%d pushed:>=%s archived:false created:%s..%s" % (MIN_STARS, cutoff, day, day)
            org, personal, total, pages = [], 0, 0, 0
            for page in range(1, 11):
                res = gh("search/repositories", {"q": q, "per_page": 100, "page": page})
                pages += 1
                time.sleep(
                    2.3
                )  # the search API allows 30 calls a minute, and about 8 quick ones before a secondary limit
                total = res["total_count"]
                for r in res["items"]:
                    if r["owner"]["type"] == OWNER_TYPE:
                        org.append(repo_facts(r))
                    else:
                        personal += 1
                if page * 100 >= total:
                    break
            return {
                "day": day.isoformat(),
                "total": total,
                "org": org,
                "personal": personal,
                "truncated": total > 1000,
                "pages": pages,
            }

        return self._cached("search", day.isoformat(), fetch)


def verdict(reader, facts):
    """`fails` on a repo, reading conditions 5 and 6 only when the cheap conditions hold. Returns (failed, facts)."""
    failed = [c for c in fails(facts, reader.on) if c in CHEAP]
    if failed:
        return failed, facts
    facts = dict(facts, **reader.git(facts["name"]))
    return fails(facts, reader.on), facts


def funnel(failures, start):
    """How many repos each condition removes, in the order of CONDITIONS: a repo is removed by the first condition it fails."""
    out, left = [], start
    for c, number, words in CONDITIONS:
        removed = sum(1 for f in failures if f and f[0] == c)
        left -= removed
        out.append({"condition": c, "number": number, "words": words, "removed": removed, "left": left})
    return out


def entry(facts, league, **extra):
    """A panel entry: what scan.py and api_signals.py read (`category` is always null: the rule gives a repo no kind),
    then the facts that made the repo pass."""
    e = {
        "name": facts["name"],
        "league": league,
        "category": None,
        "stars": facts["stars"],
        "created_at": facts["created"],
        "pushed_at": facts["pushed"],
        "default_branch": facts["default_branch"],
        "size_kb": facts["size_kb"],
        "language": facts["language"],
    }
    e.update(extra)
    e["facts"] = {
        k: facts[k]
        for k in (
            "owner",
            "owner_type",
            "private",
            "archived",
            "fork",
            "created",
            "pushed",
            "files",
            "files_cut",
            "early_commits",
            "early_scan",
            "early_total",
            "early_cut",
            "tip",
        )
    }
    return e


def ross_names():
    """Every name the ROSS Index links, as written on the editions' pages, with the editions that link it (oldest first)."""
    ross = read_json(ROSS)
    order = {e["id"]: i for i, e in enumerate(ross["editions"])}
    names = {}
    for e in ross["editions"]:
        for name in e["repos"]:
            names.setdefault(name.lower(), [name, []])[1].append(e["id"])
    return {v[0]: sorted(set(v[1]), key=lambda e: order[e]) for v in names.values()}, ross


def build_rule_pro(reader, workers):
    names, ross = ross_names()
    order = [e["id"] for e in ross["editions"]]
    answered = {}
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        facts = dict(zip(names, pool.map(reader.repo, names)))
    missing = sorted(n for n, f in facts.items() if f.get("missing"))
    for name, f in facts.items():
        if f.get("missing"):
            continue
        key = f.get("name", "personal:" + name).lower()  # a personal repo is kept as a count only, under no name
        slot = answered.setdefault(key, {"facts": f, "editions": set()})
        slot["editions"].update(names[name])
    repos = list(answered.values())
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        results = list(
            pool.map(
                lambda s: verdict(reader, s["facts"]) if "name" in s["facts"] else (["organisation"], s["facts"]), repos
            )
        )
    failures = [f for f, _ in results]
    out = []
    for slot, (failed, f) in zip(repos, results):
        if not failed:
            eds = sorted(slot["editions"], key=order.index)
            out.append(entry(f, "pro", ross=eds))
    out.sort(key=lambda e: e["name"].lower())
    info = {
        "names": len(names),
        "missing": len(missing),
        "missing_names": missing,
        "repos": len(repos),
        "funnel": funnel(failures, len(repos)),
        "passed": len(out),
        "ross": {"url": ross["url"], "read_on": ross["read_on"], "editions": len(order)},
    }
    return out, info


def build_rule_ladder(reader, pro, seed, size, workers):
    rng = random.Random(seed)
    cutoff = (reader.on - dt.timedelta(days=ACTIVE_DAYS)).isoformat()
    span = (CREATED_BEFORE - RULE_FIRST_DAY).days
    days = [
        RULE_FIRST_DAY + dt.timedelta(days=d) for d in rng.sample(range(span), span)
    ]  # every creation day, in a drawn order
    pro_names = {e["name"].lower() for e in pro}
    passed, steps, failures, seen = {}, [], [], set()
    for day in days:
        found = reader.search_day(day, cutoff)
        for f in found["org"]:  # a cache written before `owner` was kept: its `name` is GitHub's full_name
            f.setdefault("owner", f["name"].split("/")[0])
        cands = [f for f in found["org"] if f["name"].lower() not in pro_names and f["name"].lower() not in seen]
        seen.update(f["name"].lower() for f in cands)
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            results = list(pool.map(lambda f: verdict(reader, f), cands))
        day_pass = 0
        for failed, f in results:
            failures.append(failed)
            if not failed:
                passed[f["name"]] = f
                day_pass += 1
        failures += [["organisation"]] * found["personal"]
        steps.append(
            {
                "day": day.isoformat(),
                "found": found["total"],
                "personal": found["personal"],
                "org": len(found["org"]),
                "pro_left_out": len(found["org"]) - len(cands),
                "passed": day_pass,
                "pool": len(passed),
                "truncated": found["truncated"],
            }
        )
        print(
            "ladder: %s found %d, organisations %d, passed %d, pool %d (calls %d)"
            % (day, found["total"], len(found["org"]), day_pass, len(passed), reader.calls),
            flush=True,
        )
        if len(passed) >= size:
            break
    drawn = rng.sample(sorted(passed), min(size, len(passed)))
    out = sorted((entry(passed[n], "ladder") for n in drawn), key=lambda e: e["name"].lower())
    considered = len(failures)
    info = {
        "seed": seed,
        "first_day": RULE_FIRST_DAY.isoformat(),
        "last_day": (CREATED_BEFORE - dt.timedelta(days=1)).isoformat(),
        "span_days": span,
        "days_taken": len(steps),
        "steps": steps,
        "considered": considered,
        "funnel": funnel(failures, considered),
        "pool": len(passed),
        "drawn": len(out),
        "pool_names": sorted(passed),
    }  # every repo of the pool is an organisation's: the draw can be made again from it
    return out, info


def build_rule(seed, size, workers, on):
    """Both leagues on the day `on`: the cache of that day is read, so a build for a day already built makes no call."""
    reader = Reader(on)
    pro, pro_info = build_rule_pro(reader, workers)
    print(
        "pro scene under the rule: %d repos (%d ROSS names, calls so far %d)"
        % (len(pro), pro_info["names"], reader.calls),
        flush=True,
    )
    ladder, ladder_info = build_rule_ladder(reader, pro, seed, size, workers)
    write_json(DATA / "panel_pro.json", pro)
    write_json(DATA / "panel_ladder.json", ladder)
    write_json(
        DATA / "panel_rule.json",
        {
            "built_on": on.isoformat(),
            "rule": RULE,
            "conditions": [[c, n, w] for c, n, w in CONDITIONS],
            "left_out": sorted(LEFT_OUT),
            "pro": pro_info,
            "ladder": ladder_info,
        },
    )
    print(
        "ladder under the rule: %d drawn from a pool of %d over %d days; API calls this run: %d"
        % (len(ladder), ladder_info["pool"], ladder_info["days_taken"], reader.calls)
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["rule"])
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument(
        "--on",
        type=dt.date.fromisoformat,
        default=dt.date.today(),
        help="the day of the build, whatever the clock says: its cache is data/raw/rule/<day>/",
    )
    a = ap.parse_args()
    build_rule(RULE_SEED, LADDER_SIZE, a.jobs, a.on)
