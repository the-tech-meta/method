"""Build the two leagues under one rule: `panel.py rule --on <day> --as-of <day>` writes data/panel_pro.json,
data/panel_ladder.json and data/panel_rule.json (the day of the build, the page's date, the rule, each league's funnel, the
ladder's days and pool).

The rule is one for both leagues and is read on the day the panels are built. A repo passes when: 1. its owner is an
organisation (GitHub's owner type); 2. it is public, not archived, not a fork; 3. it had a push in the last ACTIVE_DAYS
days; 4. it has MIN_FILES files or more at the tip of its default branch; 5. it was already active ROLL_MONTHS months before
the page's last monthly date, or earlier: MIN_COMMITS commits or more in the WINDOW_DAYS days before at least one of the
page's monthly dates from the first one to the window's start, the monthly date ROLL_MONTHS months before the last
(`windows`); 6. its owner is not in LEFT_OUT (a maker of a coding agent the page counts, a company one of them bought, or an
owner tied to them in another way). At each issue the window's start moves one month on and the dates a repo can qualify at
grow by one: nobody leaves by condition 5. The pro scene is every repo of the ROSS Index (data/ross_index.json) that passes;
the ladder is LADDER_SIZE repos drawn at random among the repos that pass and have MIN_STARS stars or more, the pro scene left
out. Conditions 4 and 5 are read through the API (the recursive tree, the commit history), so both panels are rebuilt with no
clone.

API answers are cached under data/raw/rule/<day>/, so a second build for the same day makes no call. Needs the gh CLI, logged in.
"""

import argparse
import concurrent.futures
import hashlib
import datetime as dt
import os
import random
import sys
import time
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ACTIVE_DAYS, COMMIT_DAYS, DATA, end_of_day_ts, gh, read_json, snapshot_dates, write_json

MIN_STARS = 50

# --- The rule: its thresholds, the one source the panels, the build's file and the Method tab read ------------------
OWNER_TYPE = "Organization"  # 1. GitHub's owner type
#                                3. a push in the last ACTIVE_DAYS days (common.py), counted back from the day of the build
MIN_FILES = 200  # 4. files at the tip of the default branch (blobs, links and submodules, as a scan counts)
ROLL_MONTHS = 18  # 5. already active this many months before the page's last monthly date, or earlier: commits are
WINDOW_DAYS = COMMIT_DAYS  #    read in the window behind each of the page's monthly dates up to then (as a scan's
MIN_COMMITS = 30  #    `commits90` is), and one window with this many or more passes, merges left out
LADDER_SIZE = 200  # the ladder: this many repos, with MIN_STARS stars or more
RULE_FIRST_DAY = dt.date(
    2007, 10, 29
)  # the ladder's creation days run from GitHub's first repo (its search answers none before)
RULE_SEED = 20261122  # the seed of the ladder's draw under the rule
# The window a cache written before the rolling rule (on 2026-11-22) holds as `early_commits`: the one behind this date
CACHED_EARLY_DAY = "2025-01-17"


def windows(as_of):
    """The page's monthly dates a repo can show condition 5 at: from the grid's first date (common.snapshot_dates) to the
    window's start, the monthly date ROLL_MONTHS months before `as_of`, the page's last. One more at each issue."""
    grid = snapshot_dates(as_of)
    if len(grid) <= ROLL_MONTHS:
        raise ValueError("the grid ending on %s has no date %d months back" % (as_of, ROLL_MONTHS))
    return grid[: len(grid) - ROLL_MONTHS]


def rule(as_of):
    """The rule as data/panel_rule.json carries it and the Method tab reads it: the thresholds, and the dates of condition 5
    for the page whose last monthly date is `as_of`."""
    days = [d.isoformat() for d in windows(as_of)]
    return {
        "owner_type": OWNER_TYPE,
        "active_days": ACTIVE_DAYS,
        "min_files": MIN_FILES,
        "roll_months": ROLL_MONTHS,
        "min_commits": MIN_COMMITS,
        "commit_days": WINDOW_DAYS,
        "first_day": days[0],
        "window_start": days[-1],
        "windows": days,
        "min_stars": MIN_STARS,
        "ladder_size": LADDER_SIZE,
    }


# The conditions, in the order `fails` tries them and the funnel counts them (the cheap facts first), each with its number.
CONDITIONS = (
    ("organisation", 1, "owned by an organisation"),
    ("public", 2, "public"),
    ("not_archived", 2, "not archived"),
    ("not_fork", 2, "not a fork"),
    ("pushed", 3, "a push in the last %d days" % ACTIVE_DAYS),
    ("not_vendor", 6, "owner not a coding-agent maker, bought by one or named with them"),
    ("files", 4, "%d files or more at the tip" % MIN_FILES),
    (
        "already_active",
        5,
        "already active %d months ago or earlier: %d commits or more in the %d days before one of the monthly dates up "
        "to the window's start" % (ROLL_MONTHS, MIN_COMMITS, WINDOW_DAYS),
    ),
)
CHEAP = ("organisation", "public", "not_archived", "not_fork", "pushed", "not_vendor")

ROSS = DATA / "ross_index.json"  # which repo was in which edition of the ROSS Index
CACHE = DATA / "raw" / "rule"  # what the API answered, per day of build (data/raw/ is not tracked)
EARLY_PAGES = 30  # commits of a window read per repo: 3,000 at most, then the count is a floor
LOW_QUOTA = 500  # wait when the REST or GraphQL quota (shared with other jobs on the same token) is under this

# The GitHub owners that stay out of both leagues (condition 6), lowercase. The tie says why: "maker", a maker of a coding agent
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
    "azure": {
        "tools": ["copilot"],
        "tie": "named",
        "fact": 'Microsoft Azure: the organisation\'s profile is "Microsoft Azure", "APIs, SDKs and open source projects from '
        "Microsoft Azure\", and links docs.microsoft.com; Microsoft is left out as GitHub's parent. Read on 2026-11-27",
        "link": "https://github.com/Azure",
    },
    "microsoftdocs": {
        "tools": ["copilot"],
        "tie": "named",
        "fact": 'Microsoft Docs: the organisation\'s profile is "Microsoft Docs", "The modern documentation service for '
        "Microsoft\", and links learn.microsoft.com; Microsoft is left out as GitHub's parent. Read on 2026-11-27",
        "link": "https://github.com/MicrosoftDocs",
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
    "google-deepmind": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": 'Google DeepMind: the organisation\'s profile is "Google DeepMind"; Google makes Gemini CLI and Jules. Read '
        "on 2026-11-27",
        "link": "https://github.com/google-deepmind",
    },
    "googlecloudplatform": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": 'Google Cloud Platform: the organisation\'s profile is "Google Cloud Platform" and links cloud.google.com; '
        "Google makes Gemini CLI and Jules. Read on 2026-11-27",
        "link": "https://github.com/GoogleCloudPlatform",
    },
    "firebase": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": "Firebase: the organisation's profile links firebase.google.com; Google makes Gemini CLI and Jules. Read on "
        "2026-11-27",
        "link": "https://github.com/firebase",
    },
    "flutter": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": "Flutter: the organisation's profile reads \"Flutter is Google's UI toolkit\"; Google makes Gemini CLI and "
        "Jules. Read on 2026-11-27",
        "link": "https://github.com/flutter",
    },
    "cdapio": {
        "tools": ["gemini", "jules"],
        "tie": "maker",
        "fact": 'CDAP: the organisation\'s profile reads "CDAP is now part of Google Cloud"; Google makes Gemini CLI and '
        "Jules. Read on 2026-11-27",
        "link": "https://github.com/cdapio",
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
    "charmbracelet": {
        "tools": [],
        "tie": "named",
        "fact": "Charm makes Crush, a coding agent the scan reads (its CRUSH.md) and the page does not count, so its own "
        'repo measures its own product. Its repo\'s description: "Glamourous agentic coding for all". Named on '
        "2026-11-27; the organisation's other repos of the ROSS Index fail the rule (glow, 54 files; soft-serve, "
        "archived)",
        "link": "https://github.com/charmbracelet/crush",
    },
}


# --- The rule ----------------------------------------------------------------------------------------------------------------


def fails(facts, on, as_of):
    """The conditions of the rule a repo fails on the day `on` (a date), for the page whose last monthly date is `as_of`, in
    the order of CONDITIONS; [] when it passes. `facts` holds what `repo_facts` and `Reader.git` read. Condition 6 reads `owner`,
    the owner's login as GitHub answers it today, not the name as a list types it: a repo renamed or moved under a vendor's
    organisation is left out. Condition 5 reads `windows`, the commits counted behind each monthly date: one of the dates of
    `windows(as_of)` with MIN_COMMITS or more passes. A fact that was not read (missing or None) fails its condition.
    A file count from a tree GitHub cut is a floor, and so is a commit count cut: a floor at the threshold passes."""
    cutoff = (on - dt.timedelta(days=ACTIVE_DAYS)).isoformat()
    pushed, files = facts.get("pushed"), facts.get("files")
    days = {d.isoformat() for d in windows(as_of)}
    counted = [w["commits"] for w in facts.get("windows") or [] if w["day"] in days]
    holds = {
        "organisation": facts.get("owner_type") == OWNER_TYPE,
        "public": facts.get("private") is False,
        "not_archived": facts.get("archived") is False,
        "not_fork": facts.get("fork") is False,
        "pushed": bool(pushed) and pushed >= cutoff,
        "not_vendor": bool(facts.get("owner")) and facts["owner"].lower() not in LEFT_OUT,
        "files": files is not None and files >= MIN_FILES,
        "already_active": any(n is not None and n >= MIN_COMMITS for n in counted),
    }
    return [c for c, _, _ in CONDITIONS if not holds[c]]


def repo_facts(r):
    """The facts of conditions 1 to 3 and 6, from a REST repo or a search item, which carry the same fields. `name` and
    `owner` are the ones GitHub answers (a REST call follows a rename or a transfer), never the name the call was made with."""
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


def window_edges(day):
    """A scan's window behind a monthly date: (hi - WINDOW_DAYS days, hi], hi the end of that day in UTC."""
    hi = end_of_day_ts(dt.date.fromisoformat(day))
    return hi - WINDOW_DAYS * 86400, hi


HISTORY = """%s: history(since:"%s", until:"%s", first:100%s) { totalCount pageInfo { hasNextPage endCursor }
      nodes { committedDate parents { totalCount } } }"""
Q_WINDOWS = """query($owner:String!, $name:String!) {
  repository(owner:$owner, name:$name) { defaultBranchRef { name target { ... on Commit { oid tree { oid }
    at: history(until:"%s", first:1) { nodes { oid committedDate tree { oid } } }
    %s } } } } }"""


def stamp(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_ts(iso):
    return int(dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


def history_query(days, on, after=None):
    """One GraphQL query for the windows behind `days`, one alias each (w0, w1...), from the cursor `after` when given (one
    window only): with it comes the default branch's tip as of the day of the build `on` (`at`: the newest commit of its
    history dated by the end of that day, as a scan picks a snapshot), and its tree."""
    parts = []
    for i, day in enumerate(days):
        lo, hi = window_edges(day)
        parts.append(HISTORY % ("w%d" % i, stamp(lo + 1), stamp(hi), ', after:"%s"' % after if after else ""))
    return Q_WINDOWS % (stamp(end_of_day_ts(on)), "\n    ".join(parts))


def count_nodes(day, history):
    """The commits of one page of a window: those whose commit date falls in the window, merges (two parents or more) left out."""
    lo, hi = window_edges(day)
    return sum(1 for n in history["nodes"] if lo < to_ts(n["committedDate"]) <= hi and n["parents"]["totalCount"] < 2)


def read_windows(name, days, decided, on):
    """Condition 5 through the API, with no clone, for the windows behind `days` (in date order): what scan.read_commits counts
    as a snapshot's `commits90`, the commits of the default branch's history (every ancestor of its tip, as `git log` walks it,
    not the first parents only) whose commit date falls in the window, merges left out. GitHub's history answers by the tip of
    today, so a history rewritten since answers fewer, or none. All the windows' first pages come in one query; a window is read
    on, page after page (EARLY_PAGES at most), only while its count is under MIN_COMMITS and no earlier window reached it
    (`decided` says whether a window read before did): a count stopped earlier is a floor (`cut`). Returns
    ({day: {"commits", "total", "cut"}}, the tip as of `on` (its oid, commit date and tree, or None), the calls made): a build
    for a past day reads the tree that day had, not today's."""
    owner, repo = name.split("/", 1)
    d = gh(history_query(days, on), {"owner": owner, "name": repo}, graphql=True)
    calls = 1
    ref = (((d or {}).get("data") or {}).get("repository") or {}).get("defaultBranchRef")
    if not ref or not ref.get("target"):  # an empty repository: no tip, no tree, no commit
        return {day: {"commits": 0, "total": 0, "cut": False} for day in days}, None, calls
    t = ref["target"]
    out = {}
    for i, day in enumerate(days):
        h = t["w%d" % i]
        counted, pages = count_nodes(day, h), 1
        while h["pageInfo"]["hasNextPage"] and counted < MIN_COMMITS and not decided and pages < EARLY_PAGES:
            p = gh(history_query([day], on, h["pageInfo"]["endCursor"]), {"owner": owner, "name": repo}, graphql=True)
            calls += 1
            h = p["data"]["repository"]["defaultBranchRef"]["target"]["w0"]
            counted += count_nodes(day, h)
            pages += 1
        out[day] = {"commits": counted, "total": t["w%d" % i]["totalCount"], "cut": h["pageInfo"]["hasNextPage"]}
        decided = decided or counted >= MIN_COMMITS
    at = t["at"]["nodes"]
    return out, (at[0] if at else None), calls


def read_tree(name, tree):
    """Condition 4: the entries of the tip's recursive tree that are not folders (files, links, submodules), as a scan's
    `git ls-tree -r`, counted inside gh so that a tree of 7 MB is not held. A tree GitHub cut gives a floor (`files_cut`)."""
    t = gh(
        "repos/%s/git/trees/%s" % (name, quote(tree)),
        {"recursive": 1},
        jq='{n: ([.tree[] | select(.type != "tree")] | length), cut: .truncated}',
        missing=("404", "409", "410", "451"),
    )
    return {"files": t["n"], "files_cut": bool(t["cut"])} if t else {"files": 0, "files_cut": False}


class Reader:
    """The API's answers for one day of build, cached under data/raw/rule/<day>/, so that a second build that day costs nothing.
    A personal account's repo is never written: its answer is cached as its owner type alone. `as_of` is the page's last
    monthly date, whose windows condition 5 reads."""

    def __init__(self, on, as_of):
        self.on, self.as_of, self.root, self.calls, self.since_check = on, as_of, CACHE / on.isoformat(), 0, 0
        self.days = [d.isoformat() for d in windows(as_of)]

    def path(self, kind, key):
        return (
            self.root / kind / (hashlib.sha1(key.lower().encode()).hexdigest()[:20] + ".json")
        )  # no name in a file name

    def _cached(self, kind, key, fetch, cost=1):
        path = self.path(kind, key)
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
        """Conditions 4 and 5: the tip as of the day of the build, its files, and the commits behind each of the rule's monthly
        dates. Cached per repo (`git/`: the tip and its files; one written on the day of the build holds that day's tip) and per repo and window (`window/`, under "<name>@<day>"), so that the next issue reads
        the one new window only. A `git/` cache written before the rolling rule holds the window behind CACHED_EARLY_DAY as
        `early_commits`, which is read as that window."""
        tree_path = self.path("git", name)
        tip = read_json(tree_path) if tree_path.exists() else None
        if tip and "early_commits" not in tip and "tip_date" not in tip:
            tip = None  # written on 2026-11-27 before the tip's date was kept: read again
        got = {}
        for day in self.days:
            p = self.path("window", "%s@%s" % (name, day))
            if p.exists():
                got[day] = read_json(p)
            elif day == CACHED_EARLY_DAY and tip and "early_commits" in tip:
                got[day] = {"commits": tip["early_commits"], "total": tip["early_total"], "cut": tip["early_cut"]}
        todo = [d for d in self.days if d not in got]
        if todo or tip is None:
            self.guard()
            decided = not todo or any(w["commits"] >= MIN_COMMITS for d, w in got.items() if d < todo[0])
            read, at, calls = read_windows(name, todo or self.days[:1], decided, self.on)
            self.calls += calls
            for day in todo:
                got[day] = read[day]
                write_json(self.path("window", "%s@%s" % (name, day)), read[day])
            if tip is None:
                tip = {"files": 0, "files_cut": False, "tip": None, "tip_date": None}
                if at:
                    tip = dict(read_tree(name, at["tree"]["oid"]), tip=at["oid"], tip_date=at["committedDate"][:10])
                    self.calls += 1
                write_json(tree_path, tip)
        ws = [dict(got[d], day=d) for d in self.days]
        active = [w["day"] for w in ws if w["commits"] >= MIN_COMMITS]
        return {
            "tip": tip["tip"],
            "tip_date": tip.get("tip_date"),
            "files": tip["files"],
            "files_cut": tip["files_cut"],
            "windows": ws,
            "active_on": active[0] if active else None,
            "best": max(w["commits"] for w in ws),
        }

    def search_day(self, day, cutoff):
        """The ladder's query for one creation day: the organisations' repos with their facts; the others counted, never named.
        `read_on` is the day GitHub answered (a cache written before it was kept was answered on the day of the build)."""

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
                "read_on": dt.date.today().isoformat(),
                "pages": pages,
            }

        found = self._cached("search", day.isoformat(), fetch)
        found.setdefault("read_on", self.on.isoformat())
        return found


def verdict(reader, facts):
    """`fails` on a repo, reading conditions 4 and 5 only when the cheap conditions hold. Returns (failed, facts)."""
    failed = [c for c in fails(facts, reader.on, reader.as_of) if c in CHEAP]
    if failed:
        return failed, facts
    facts = dict(facts, **reader.git(facts["name"]))
    return fails(facts, reader.on, reader.as_of), facts


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
            "tip",
            "tip_date",
            "windows",
            "active_on",
            "best",
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


ORDER = (
    "each creation day ranked by the SHA-256 of '<seed>:<day>': a day's place is given by the seed and the day alone"
)


def day_order(seed, first, last):
    """Every creation day from `first` to `last`, in the order the seed gives. A day's place is the SHA-256 of
    "<seed>:<day>", so the days of a span keep their order when the span grows at the next issue."""
    days = [first + dt.timedelta(days=d) for d in range((last - first).days + 1)]
    return sorted(days, key=lambda d: hashlib.sha256(("%d:%s" % (seed, d.isoformat())).encode()).hexdigest())


def build_rule_ladder(reader, pro, seed, size, workers):
    """The creation days run from RULE_FIRST_DAY to the day before the build: a repo created after the window's start can
    pass condition 5 by commits older than the repo (a history brought in when it was created), so no creation day is left
    out of the draw. The days are taken in the seed's order, each day's repos read whole, until `size` or more pass; then
    `size` are drawn from them with a generator of the same seed."""
    cutoff = (reader.on - dt.timedelta(days=ACTIVE_DAYS)).isoformat()
    last = reader.on - dt.timedelta(days=1)
    days = day_order(seed, RULE_FIRST_DAY, last)
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
                "read_on": found["read_on"],
            }
        )
        print(
            "ladder: %s found %d, organisations %d, passed %d, pool %d (calls %d)"
            % (day, found["total"], len(found["org"]), day_pass, len(passed), reader.calls),
            flush=True,
        )
        if len(passed) >= size:
            break
    drawn = random.Random(seed).sample(sorted(passed), min(size, len(passed)))
    out = sorted((entry(passed[n], "ladder") for n in drawn), key=lambda e: e["name"].lower())
    considered = len(failures)
    info = {
        "seed": seed,
        "first_day": RULE_FIRST_DAY.isoformat(),
        "last_day": last.isoformat(),
        "span_days": len(days),
        "order": ORDER,
        "days_taken": len(steps),
        "steps": steps,
        "considered": considered,
        "funnel": funnel(failures, considered),
        "pool": len(passed),
        "drawn": len(out),
        "pool_names": sorted(passed),
    }  # every repo of the pool is an organisation's: the draw can be made again from it
    return out, info


def build_rule(seed, size, workers, on, as_of, leagues=("pro", "ladder")):
    """Both leagues on the day `on`, for the page whose last monthly date is `as_of`: the cache of that day is read, so a build
    for a day already built makes no call. With the pro scene alone, data/panel_ladder.json and the ladder's part of
    data/panel_rule.json are left as they are (a step of a build, not a build)."""
    reader = Reader(on, as_of)
    pro, pro_info = build_rule_pro(reader, workers)
    print(
        "pro scene under the rule: %d repos (%d ROSS names, calls so far %d)"
        % (len(pro), pro_info["names"], reader.calls),
        flush=True,
    )
    if "ladder" in leagues:
        ladder, ladder_info = build_rule_ladder(reader, pro, seed, size, workers)
        write_json(DATA / "panel_ladder.json", ladder)
    else:
        ladder_info = read_json(DATA / "panel_rule.json")["ladder"]
    write_json(DATA / "panel_pro.json", pro)
    write_json(
        DATA / "panel_rule.json",
        {
            "built_on": on.isoformat(),
            "as_of": as_of.isoformat(),
            "rule": rule(as_of),
            "conditions": [[c, n, w] for c, n, w in CONDITIONS],
            "left_out": sorted(LEFT_OUT),
            "pro": pro_info,
            "ladder": ladder_info,
        },
    )
    print("API calls this run: %d" % reader.calls)


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
    ap.add_argument(
        "--as-of",
        type=dt.date.fromisoformat,
        default=os.environ.get("METATECH_AS_OF"),
        help="the page's last monthly date (METATECH_AS_OF by default), whose grid gives condition 5's dates",
    )
    ap.add_argument("--pro-only", action="store_true", help="build the pro scene alone, the ladder left as it is")
    a = ap.parse_args()
    if not a.as_of:
        ap.error("--as-of is needed (or METATECH_AS_OF): the page's last monthly date")
    build_rule(RULE_SEED, LADDER_SIZE, a.jobs, a.on, a.as_of, ("pro",) if a.pro_only else ("pro", "ladder"))
