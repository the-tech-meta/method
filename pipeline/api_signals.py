"""Behaviour that only shows on GitHub itself, not in the git history: who opens pull requests and which bots
comment on them. Three API calls per repo, the latest LATEST_ITEMS items each, and four more for the security
settings anyone can read on a public repo (`security`): whether private vulnerability reporting is on, whether the
default branch is protected and the types of the rules on it (a ruleset of the repo or of its organisation), and how
many advisories it has published, up to LATEST_ITEMS. Secret scanning and push protection cannot be read from outside.
Writes one file per repo to data/api/; a repo that already has one is skipped.

  api_signals.py data/panel_pro.json [--jobs 4]

Only bot accounts and agent branch prefixes are tallied; human logins are never stored.
"""

import argparse
import collections
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import AS_OF, DATA, LATEST_ITEMS, gh, read_json, slug, write_json

LATEST = {"sort": "created", "direction": "desc", "per_page": LATEST_ITEMS}

# Pull requests opened by an agent: by the account that opened them...
PR_AUTHOR = {
    "copilot": r"^(?:copilot|copilot-swe-agent)(?:\[bot\])?$",
    "devin": r"^devin-ai-integration",
    "cursor": r"^cursor(?:agent)?(?:\[bot\])?$",
    "jules": r"^google-labs-jules",
    "claude": r"^claude(?:-code)?(?:\[bot\])?$",
    "codex": r"^(?:chatgpt-codex-connector|codex)(?:\[bot\])?$",
    "openhands": r"^openhands",
    "codegen": r"^codegen-sh",
    "droid": r"^factory-droid",
    "sweep": r"^sweep-ai",
    "seer": r"^seer-by-sentry",
    "opencode": r"^opencode-agent",
    "lovable": r"^lovable-dev|^gpt-engineer-app",
    "v0": r"^v0\[bot\]",
}
# ...or, when a person's account opens them, by the branch name the agent gives by default.
PR_BRANCH = {
    "codex": r"^codex/",
    "claude": r"^claude/",
    "cursor": r"^cursor/.+-[0-9a-f]{4}$",
    "copilot": r"^copilot/",
    "devin": r"^devin/",
}
PR_AUTHOR = {k: re.compile(v, re.I) for k, v in PR_AUTHOR.items()}
PR_BRANCH = {k: re.compile(v) for k, v in PR_BRANCH.items()}


def is_bot(user):
    return bool(user) and (user.get("type") == "Bot" or user.get("login", "").endswith("[bot]"))


def pr_agent(pr):
    login = (pr.get("user") or {}).get("login", "")
    for agent, rx in PR_AUTHOR.items():
        if rx.search(login):  # pyright: ignore[reportAttributeAccessIssue]  (compiled above)
            return agent
    for agent, rx in PR_BRANCH.items():
        if rx.search(pr["head"]["ref"]):  # pyright: ignore[reportAttributeAccessIssue]  (compiled above)
            return agent
    return None


def bot_tally(comments, only_pulls=False):
    tally = collections.Counter()
    for c in comments:
        if is_bot(c.get("user")) and (not only_pulls or "/pull/" in c.get("html_url", "")):
            tally[c["user"]["login"].lower()] += 1
    return dict(tally)


def ask(path, params=None):
    """One call whose failure must not cost the repo its other signals: None when it fails or answers nothing."""
    try:
        return gh(path, params)
    except RuntimeError:
        return None


def security(repo):
    """The security settings of a public repo that anyone can read: four calls. A call that fails or answers
    nothing (404) leaves its field null, which is not the same as off (false) or none (0, [])."""
    name, branch = repo["name"], repo.get("default_branch")
    pvr = ask("repos/%s/private-vulnerability-reporting" % name)
    rules = ask("repos/%s/rules/branches/%s" % (name, branch), {"per_page": LATEST_ITEMS}) if branch else None
    info = ask("repos/%s/branches/%s" % (name, branch)) if branch else None
    advisories = ask("repos/%s/security-advisories" % name, {"state": "published", "per_page": LATEST_ITEMS})
    return {
        "private_reporting": pvr.get("enabled") if isinstance(pvr, dict) else None,
        "protected": info.get("protected") if isinstance(info, dict) else None,
        # only the type of each rule: the ruleset's id, its source and the people it exempts are not kept
        "branch_rules": sorted({str(r.get("type")) for r in rules if isinstance(r, dict)})
        if isinstance(rules, list)
        else None,
        "advisories": len(advisories) if isinstance(advisories, list) else None,
    }


def signals(repo):
    name = repo["name"]
    out_path = DATA / "api" / (slug(name) + ".json")
    if out_path.exists():
        return name, "cached"
    try:
        pulls = gh("repos/%s/pulls" % name, dict(LATEST, state="all")) or []
        reviews = gh("repos/%s/pulls/comments" % name, LATEST) or []
        comments = gh("repos/%s/issues/comments" % name, LATEST) or []
        settings = security(repo)
    except RuntimeError as e:
        return name, "FAILED %s" % str(e)[:150]
    agents = collections.Counter(a for a in map(pr_agent, pulls) if a)
    write_json(
        out_path,
        {
            "name": name,
            "as_of": AS_OF.isoformat(),
            "prs": len(pulls),
            "prs_since": pulls[-1]["created_at"][:10] if pulls else None,
            "agent_prs": dict(agents),
            "bot_pr_authors": bot_tally(pulls),
            "review_comments": len(reviews),
            "review_comments_since": reviews[-1]["created_at"][:10] if reviews else None,
            "review_bots": bot_tally(reviews),
            "pr_comment_bots": bot_tally(comments, only_pulls=True),
            "security": settings,
        },
    )
    return name, "ok prs=%d agent=%d review_bots=%s" % (len(pulls), sum(agents.values()), sorted(bot_tally(reviews)))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("panel")
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    repos = read_json(a.panel)
    with ThreadPoolExecutor(a.jobs) as pool:
        for i, (name, status) in enumerate(pool.map(signals, repos), 1):
            print("[%d/%d] %s: %s" % (i, len(repos), name, status), flush=True)
