"""Scan every repo of a panel: clone without file contents, read the trees and commit
messages since the cutoff, write one JSON per repo to data/scan/, delete the clone.
A repo that already has a scan file is skipped. The instruction files of the tip are kept
under data/raw/instructions/.

  scan.py data/panel_pro.json [--jobs 4] [--only owner/repo] [--skip a/b,c/d] [--keep]

  scan.py data/panel_pro.json --reread [--keep]
      read again the commits an earlier scan read, with the rules as they are now: the way to add a
      rule without moving a published figure. Nothing else of the scan is touched.

What is read from each repo:
  - the file tree on a monthly grid (paths only), matched against fingerprints.py
  - a few small files (workflows, agent settings and hooks, MCP configs, instruction files, the
    package manager's root files, git hooks, the dependency bot's config, the security policy)
  - commit messages, for agent signatures

Nothing about people is written out: author names and emails are only tested in memory
against agent signatures.
"""

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fingerprints as fp
from common import (
    AS_OF,
    CLONES,
    COMMIT_DAYS,
    DATA,
    HOOK_ENV,
    SHALLOW_SINCE,
    end_of_day_ts,
    read_json,
    slug,
    snapshot_dates,
    write_json,
)

# every git call names its repo with -C: a repo named by the environment (inside a hook) must not win over it
ENV = dict({k: v for k, v in os.environ.items() if k not in HOOK_ENV}, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
CLONE_TIMEOUT = int(os.environ.get("METATECH_CLONE_TIMEOUT", 900))
MIN_FREE_GB = 6
MAX_BLOBS = 3000  # per repo, across all snapshots
MAX_BLOB_BYTES = 1000000  # per file: a file over it is read as one not fetched (its path counts, its text is not read)
MAX_INSTRUCTION_FILES = 40
MAX_STORED_BYTES = 200000
SAMPLE = 12  # example paths kept per rule and snapshot
CONTENT_RULES = ("workflows", "shared_settings", "mcp_config")
# Read at every snapshot too, for the checks and the security signals. Their blobs are asked for
# after those of CONTENT_RULES, so the cap never takes a workflow away from an older snapshot.
GUARD_RULES = ("pkg_files", "pkg_nested", "dependabot", "renovate", "git_hooks", "security_md")
ROOT_INSTRUCTIONS = 12  # root instruction files read per snapshot, to see what they tell an agent to run
SEP = "\x1f"


def run(cmd, timeout=900, data=None):
    return subprocess.run(cmd, input=data, capture_output=True, env=ENV, timeout=timeout)


def git(repo, *args, data=None):
    p = run(["git", "-C", str(repo), "-c", "core.quotepath=off"] + list(args), data=data)
    if p.returncode != 0:
        raise RuntimeError("git %s: %s" % (args[0], p.stderr.decode(errors="replace")[:300]))
    return p.stdout


def clone(name, dest):
    """Blobless clone of the default branch since SHALLOW_SINCE, the start of the first snapshot's window. Returns the history mode."""
    base = ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", "--single-branch", "--no-tags"]
    url = "https://github.com/%s.git" % name
    for attempt in range(3):
        p = run(base + ["--shallow-since=" + SHALLOW_SINCE, url, str(dest)], timeout=CLONE_TIMEOUT)
        if p.returncode == 0:
            return "since"
        shutil.rmtree(dest, ignore_errors=True)
        err = p.stderr.decode(errors="replace")
        if "shallow info" in err:
            break  # no commit since the cutoff on the default branch: the tip is all there is
        time.sleep(20 * (attempt + 1))  # anything else is the network or GitHub throttling
    else:
        raise RuntimeError("clone: " + err[:300])
    p = run(base + ["--depth=1", url, str(dest)], timeout=CLONE_TIMEOUT)
    if p.returncode != 0:
        raise RuntimeError("clone: " + p.stderr.decode(errors="replace")[:300])
    return "tip"


def pick_commits(repo, dates, created_at, mode):
    """For each snapshot date, the default-branch commit that was its tip (sha, tree, approx)."""
    log = git(repo, "log", "--first-parent", "--format=%H %T %ct", "HEAD").decode().split("\n")
    commits = [(s, t, int(ts)) for s, t, ts in (line.split() for line in log if line)]
    earliest = commits[-1]
    # In "tip" mode a tip older than the cutoff means the tree never changed in the window.
    constant = mode == "tip" and commits[0][2] < end_of_day_ts(dates[0])
    picked = []
    for d in dates:
        limit = end_of_day_ts(d)
        hit = next((c for c in commits if c[2] <= limit), None)
        if hit:
            picked.append((hit[0], hit[1], False))
        elif created_at <= d.isoformat() and (mode == "since" or constant):
            # Repo existed but its last commit before this date is older than the cutoff:
            # the earliest commit we have is the closest known state.
            picked.append((earliest[0], earliest[1], True))
        else:
            picked.append(None)
    return picked, commits[0]


def read_tree(repo, sha):
    """Fingerprint hits for one commit, plus the blobs whose content is worth reading."""
    hits = collections.defaultdict(lambda: {"n": 0, "root": 0, "shipped": 0, "symlink": 0, "sample": []})
    blobs, paths, n_files, code, tests, said = [], [], 0, 0, 0, []
    own_lint, released = [], set()  # custom lint files, and the plugin folders released as a package
    out = git(repo, "ls-tree", "-r", "-z", "--full-tree", sha).decode(errors="replace")
    for rec in out.split("\0"):
        if not rec:
            continue
        n_files += 1
        meta, path = rec.split("\t", 1)
        mode, _, oid = meta.split(" ")
        if fp.CODE_FILE.search(path) and not fp.NOT_OWN_CODE.search(path):
            code += 1
            tests += bool(fp.TEST_FILE.search(path) or fp.JVM_TEST_FILE.search(path))
        if ("lugin" in path or "LUGIN" in path) and (m := fp.PLUGIN_RELEASED.match(path)):
            released.add(m.group(1).lower())
        linked = fp.match_link(path) if mode in ("120000", "160000") else None
        for rule, shipped, at_root in [linked] if linked else fp.match(path):
            h = hits[rule]
            if shipped:
                h["shipped"] += 1
                continue
            if rule == "custom_lint":  # counted after the walk, once the released plugins are known
                own_lint.append((path, at_root, mode == "120000"))
                continue
            h["n"] += 1
            h["root"] += at_root
            h["symlink"] += mode == "120000"
            if rule not in fp.UNSTORED:  # a file name that may name a person is counted, never kept
                if len(h["sample"]) < SAMPLE:
                    h["sample"].append(path)
                paths.append((rule, path))
            if linked and mode == "120000":
                blobs.append(("link", path, oid, True))
            elif mode != "160000" and (
                rule in CONTENT_RULES
                or rule in GUARD_RULES
                or rule in fp.INSTRUCTION_RULES
                or (rule == "hooks_files" and path.endswith(".json"))
            ):  # a submodule's entry is another repo's commit, no blob
                blobs.append((rule, path, oid, mode == "120000"))
                if rule in fp.INSTRUCTION_RULES and at_root and mode != "160000":
                    said.append((path.count("/"), path, oid))
    for path, at_root, symlink in own_lint:
        h = hits["custom_lint"]
        if any(path.lower().startswith(folder) for folder in released):
            h["shipped"] += 1
            continue
        h["n"] += 1
        h["root"] += at_root
        h["symlink"] += symlink
        if len(h["sample"]) < SAMPLE:
            h["sample"].append(path)
        paths.append(("custom_lint", path))
    root = git(repo, "ls-tree", "-z", "--full-tree", "--name-only", sha).decode(errors="replace")
    return {
        "hits": dict(hits),
        "blobs": blobs,
        "paths": paths,
        "n_files": n_files,
        "root": sorted(x for x in root.split("\0") if x),
        "code": [tests, code],
        # the root instruction files, shallowest first: read at every snapshot
        "said": [oid for _, _, oid in sorted(said)[:ROOT_INSTRUCTIONS]],
    }


def head_paths(paths, cap=4000):
    """The matched paths of the tip that a scan keeps, up to a cap: the rules of Issue #1 (fingerprints.ISSUE1_RULES) last,
    so that the cap never takes away a path of the other rules, whose figures were already published."""
    return ([p for p in paths if p[0] not in fp.ISSUE1_RULES] + [p for p in paths if p[0] in fp.ISSUE1_RULES])[:cap]


def fetch_blobs(repo, oids):
    """Contents of the given blobs, fetched from the remote in one request. A failed fetch stops the scan: otherwise
    cat-file would fetch each missing blob alone, which can run past the timeout. A blob over MAX_BLOB_BYTES is left
    out, as if it had not been fetched, so that one repo cannot fill the memory."""
    if not oids:
        return {}
    stdin = ("\n".join(oids) + "\n").encode()
    p = run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "fetch.negotiationAlgorithm=noop",
            "fetch",
            "origin",
            "--no-tags",
            "--no-write-fetch-head",
            "--recurse-submodules=no",
            "--filter=blob:none",
            "--stdin",
        ],
        data=stdin,
    )
    if p.returncode != 0:
        raise RuntimeError("fetch of %d blobs: %s" % (len(oids), p.stderr.decode(errors="replace")[:300]))
    sizes = [line.split() for line in git(repo, "cat-file", "--batch-check", data=stdin).decode().splitlines()]
    small = [h[0] for h in sizes if len(h) == 3 and h[1] == "blob" and int(h[2]) <= MAX_BLOB_BYTES]
    if not small:
        return {}
    data = git(repo, "cat-file", "--batch", data=("\n".join(small) + "\n").encode())
    out, i = {}, 0
    while i < len(data):
        j = data.index(b"\n", i)
        head = data[i:j].split()
        i = j + 1
        if len(head) == 3:
            size = int(head[2])
            out[head[0].decode()] = data[i : i + size]
            i += size + 1
    return out


def loads_lenient(raw):
    text = raw.decode(errors="replace")
    for candidate in (text, re.sub(r"^\s*//.*$", "", text, flags=re.M)):
        try:
            return json.loads(candidate)
        except ValueError:
            pass
    return None


def read_settings(raw):
    """What a committed .claude/settings.json reveals: hooks, permissions, plugins."""
    cfg = loads_lenient(raw)
    if not isinstance(cfg, dict):
        return None
    perms = v if isinstance(v := cfg.get("permissions"), dict) else {}
    hooks = v if isinstance(v := cfg.get("hooks"), dict) else {}
    plugins = v if isinstance(v := cfg.get("enabledPlugins"), dict) else {}
    return {
        "hooks": sorted(hooks),
        "allow": len(perms.get("allow") or []),
        "deny": len(perms.get("deny") or []),
        "mode": perms.get("defaultMode"),
        "plugins": sorted(k for k, v in plugins.items() if v),
    }


def read_mcp(raw):
    cfg = loads_lenient(raw)
    if not isinstance(cfg, dict):
        return []
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    return sorted(str(k).lower() for k in servers) if isinstance(servers, dict) else []


def read_content(tree, blobs):
    """Content-based signals of one snapshot."""
    ci, ci_llm, settings, mcp = set(), False, None, set()
    for rule, path, oid, _ in tree["blobs"]:
        raw = blobs.get(oid)
        if raw is None:
            continue
        if rule == "workflows":
            text = raw.decode(errors="replace").lower()
            ci.update(k for k, rx in fp.CI_AGENTS.items() if rx.search(text))
            ci_llm = ci_llm or bool(fp.CI_LLM_KEY.search(text))
        elif rule == "shared_settings" and path.endswith(".claude/settings.json"):
            s = read_settings(raw)
            # A monorepo can carry several; the root one wins, nested ones only add hooks.
            if s and (settings is None or path == ".claude/settings.json"):
                s["hooks"] = sorted(set(s["hooks"]) | set(settings["hooks"] if settings else []))
                settings = s
            elif s:
                settings["hooks"] = sorted(set(settings["hooks"]) | set(s["hooks"]))
        elif rule == "mcp_config" and path.endswith(".json"):
            mcp.update(read_mcp(raw))
    return {"ci": sorted(ci), "ci_llm": ci_llm, "settings": settings, "mcp": sorted(mcp)}


def hook_commands(node):
    """Every command a hooks entry runs, whatever nesting its tool uses."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("command", "prompt", "bash", "powershell") and isinstance(value, str):
                yield value
            else:
                yield from hook_commands(value)
    elif isinstance(node, list):
        for value in node:
            yield from hook_commands(value)


def read_hooks(cfg, out):
    """What the hooks of one config file do: a check after an edit, a guard before an action, setup."""
    hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
    for event, entries in hooks.items() if isinstance(hooks, dict) else ():
        event = str(event).lower()
        for command in hook_commands(entries):
            kinds = {k for k, rx in fp.HOOK_CHECKS.items() if rx.search(command.lower())}
            if fp.HOOK_BEFORE.search(event):
                out["guard"] += 1
            elif fp.HOOK_AFTER.search(event) and kinds:
                out["checks"] |= kinds
            elif fp.HOOK_START.search(event):
                out["setup"] += 1
            else:
                out["other"] += 1


def read_permissions(cfg):
    """The permission rules and the sandbox of a committed .claude/settings.json."""
    perms = v if isinstance(v := cfg.get("permissions"), dict) else {}
    deny = [str(rule).lower() for rule in perms.get("deny") or []]
    sandbox = cfg.get("sandbox")
    return {
        "allow": len(perms.get("allow") or []),
        "deny": len(deny),
        "ask": len(perms.get("ask") or []),
        "secrets": any(fp.SECRET_RULE.search(rule) for rule in deny),
        "sandbox": isinstance(sandbox, dict) and sandbox.get("enabled") is True,
        "no_bypass": "disable" in (cfg.get("disableBypassPermissionsMode"), perms.get("disableBypassPermissionsMode")),
        "mcp_all": cfg.get("enableAllProjectMcpServers") is True,
    }


COMMAND_KEY = re.compile(
    r"^(\s*(?:-\s+)?)(?:run|script|command|commands|cmd|args|afterbuild|[\w-]*[-_](?:command|cmd|script))\s*:\s*(.*)$"
)
USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*[\"']?(\S+)")


def workflow_commands(text):
    """What a workflow runs: the actions it uses and the commands of its run blocks and command inputs.

    Step names, path filters, matrix values and an agent's prompt are left out: a check is counted
    where it is run, not where it is named.
    """
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if m := USES.match(line):
            out.append(m.group(1))
        elif m := COMMAND_KEY.match(line):
            indent, value = len(m.group(1)), m.group(2).strip()  # the key's column, past the dash of a list item
            if value and not value.startswith(("|", ">")):
                out.append(value)
                continue
            # a block: the lines indented deeper than its key
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                out.append(lines[i].strip())
                i += 1
    return "\n".join(out)


def with_scripts(commands, scripts):
    """The commands, followed by the root package.json scripts they call, two levels down."""
    seen = set()
    for _ in range(2):
        called = {name for name in fp.SCRIPT_CALL.findall(commands) if name in scripts} - seen
        if not called:
            break
        seen |= called
        commands += "\n" + "\n".join(scripts[name] for name in sorted(called))
    return commands


def drop_comments(text):
    """A workflow's text without its comments: a comment line, then a comment after a value (`uses: x@sha # v4`)."""
    return re.sub(r"\s#\s.*$", "", re.sub(r"^\s*#.*$", "", text, flags=re.M), flags=re.M)


def read_workflows(texts, owner="", scripts=None):
    """What the workflows of one snapshot run and how they hold an agent. Comments are dropped.

    `owner` is the repo's own account, whose actions are not a third party's; `scripts` are the
    scripts of the root package.json, lowercased.
    """
    texts = [drop_comments(t) for t in texts]  # `# zizmor: ignore[...]` too
    pins = [0, 0, 0, 0]  # uses pinned to a commit, to a tag or branch; the same two for third-party actions
    for text in texts:
        for action_owner, ref in fp.ACTION_USE.findall(text):
            sha = bool(re.fullmatch(r"[0-9a-f]{40}", ref))
            pins[0 if sha else 1] += 1
            if action_owner not in fp.FIRST_PARTY_ACTIONS and action_owner != owner:
                pins[2 if sha else 3] += 1
    run = [with_scripts(workflow_commands(t), scripts or {}) for t in texts]
    with_agent = [t for t in texts if any(rx.search(t) for rx in fp.CI_AGENTS.values())]
    fence = {k for k, rx in fp.CI_AGENT_FENCE.items() if any(rx.search(t) for t in with_agent)}
    if any(fp.FORK_TRIGGER.search(block) for t in with_agent for block in fp.ON_BLOCK.findall(t)):
        fence.add("target")
    return {
        "ci": sorted(k for k, rx in fp.CI_CHECKS.items() if any(rx.search(t) for t in run)),
        "scanners": sorted(k for k, rx in fp.CI_SCANNERS.items() if any(rx.search(t) for t in run)),
        "pins": pins,
        "agent": {"n": len(with_agent), "fence": sorted(fence)} if with_agent else None,
    }


def token_scoped(text):
    """Whether a workflow (comments dropped) scopes the token it hands every job: a `permissions` key at its top or in
    each job, other than write-all. A job's own key wins over the workflow's."""
    top = fp.TOP_PERMISSIONS.findall(text)
    top_ok = bool(top) and "write-all" not in top[-1]
    jobs = fp.JOBS_KEY.search(text)
    if not jobs:
        return top_ok
    scoped, job_indent, body_indent, current = [], None, None, None
    for line in text[jobs.end() :].split("\n"):
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            break  # the next key of the workflow: the jobs are over
        if job_indent is None or indent <= job_indent:
            job_indent, body_indent = indent, None  # a job's name
            if current is not None:
                scoped.append(current)
            current = top_ok
            continue
        if body_indent is None:
            body_indent = indent  # the job's own keys sit at the depth of its first line
        if indent == body_indent and (m := re.match(r"\s*permissions\s*:[ \t]*(.*)$", line)):
            current = "write-all" not in m.group(1)
    if current is not None:
        scoped.append(current)
    return all(scoped) if scoped else top_ok


def checkouts(text):
    """[checkout steps, those that keep the token off the disk] in a workflow (comments dropped)."""
    lines = text.split("\n")
    found = [0, 0]
    for m in fp.CHECKOUT.finditer(text):
        at = text.count("\n", 0, m.start())
        indent = len(m.group(1))
        start, dash = at, indent if m.group(2) else None
        while dash is None and start > 0:  # `uses` is not the step's first key: find the dash that opens it
            start -= 1
            prev = lines[start]
            if prev.strip().startswith("- ") and len(prev) - len(prev.lstrip()) < indent:
                dash = len(prev) - len(prev.lstrip())
        end = at + 1
        while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > (dash or 0)):
            end += 1
        found[0] += 1
        found[1] += bool(fp.NO_PERSIST.search("\n".join(lines[start:end])))
    return found


def read_supply(workflows, scripts=None):
    """Security as a whole in the workflows of one snapshot: what they do to the supply chain and the code they ship
    (CI_SUPPLY, CI_SUPPLY_INPUTS), how many scope their token, and how many checkouts keep it off the disk.

    `workflows` are (path, lowercased text); a token and a checkout are read in the YAML ones only.
    """
    texts = [(path, drop_comments(text.replace("\r", ""))) for path, text in workflows]  # a file saved with CRLF
    run = [with_scripts(workflow_commands(text), scripts or {}) for _, text in texts]
    yaml = [text for path, text in texts if re.search(r"\.ya?ml$", path)]
    found = {k for k, rx in fp.CI_SUPPLY.items() if any(rx.search(t) for t in run)}
    found |= {k for k, rx in fp.CI_SUPPLY_INPUTS.items() if any(rx.search(t) for _, t in texts)}
    pulls = [checkouts(text) for text in yaml]
    return {
        "supply": sorted(found),
        "token": [len(yaml), sum(map(token_scoped, yaml))],
        "checkout": [sum(c[0] for c in pulls), sum(c[1] for c in pulls)],
    }


def indent_of(line):
    return len(line) - len(line.lstrip())


# A mapping key on a line of its own, past the dash of a list item: its name and the value after it.
KEY_LINE = re.compile(r"^[ \t]*(?:-[ \t]+)?[\"']?([\w-]+)[\"']?[ \t]*:(?:[ \t]+(.*))?$")
STEP_USES = re.compile(r"^([ \t]*)(-[ \t]+)?uses[ \t]*:[ \t]*[\"']?([^\s\"']+)", re.M)


def triggers(text):
    """The events a workflow (comments dropped) runs on, each with what is written under it: {event: its filters}."""
    out = collections.defaultdict(list)
    for block in fp.ON_BLOCK.findall(text):
        first, _, rest = block.partition("\n")
        first = first.strip()
        if first.startswith("{"):  # on: {push: {paths: [a]}}: every event named in it, with the whole mapping
            for name in re.findall(r"([\w-]+)[\"']?[ \t]*:", first):
                out[name].append(first)
        elif first:  # on: push, on: [push, pull_request]
            for name in re.findall(r"[\w-]+", first):
                out[name].append("")
        top, current = None, None
        for line in rest.split("\n"):
            if not line.strip():
                continue
            if top is None or indent_of(line) <= top:
                top = indent_of(line) if top is None else top
                m = KEY_LINE.match(line) or re.match(r"^[ \t]*-[ \t]+[\"']?([\w-]+)[\"']?[ \t]*()$", line)
                current = m.group(1) if m else None
                if current:
                    out[current].append(m.group(2) or "")
            elif current:
                out[current].append(line.strip())
    return {k: "\n".join(v) for k, v in out.items()}


def job_keys(text):
    """The keys of each job of a workflow (comments dropped): [{key: [its value on the line, then the lines under it]}]."""
    found = fp.JOBS_KEY.search(text)
    if not found:
        return []
    out, job_indent, body_indent, key = [], None, None, None
    for line in text[found.end() :].split("\n"):
        if not line.strip():
            continue
        indent = indent_of(line)
        if indent == 0:
            break  # the next key of the workflow: the jobs are over
        if job_indent is None or indent <= job_indent:
            job_indent, body_indent, key = indent, None, None  # a job's name
            out.append({})
            continue
        if body_indent is None:
            body_indent = indent  # the job's own keys sit at the depth of its first line
        if indent == body_indent:
            m = KEY_LINE.match(line)
            key = m.group(1) if m else None
            if key:
                out[-1][key] = [m.group(2) or ""]
        elif indent > body_indent and key:
            out[-1][key].append(line.strip())
    return out


def steps_using(text):
    """Every step or job of a workflow (comments dropped) that uses an action: (the action as written, the step's lines)."""
    lines = text.split("\n")
    for at, line in enumerate(lines):
        m = STEP_USES.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        start, floor = at, indent if m.group(2) else indent - 1  # without a dash, the keys beside `uses` belong to it
        for k in range(at - 1, max(at - 51, -1), -1) if not m.group(2) else ():  # a step's keys before `uses`: a few
            prev = lines[k]
            if not prev.strip() or indent_of(prev) >= indent:
                continue
            dash = re.match(r"^([ \t]*)-[ \t]+", prev)
            if dash and len(dash.group(0)) == indent:  # `uses` is not the step's first key: the dash that opens it
                start, floor = k, len(dash.group(1))
            break
        end = at + 1
        # a step's inputs, up to a bound and to the next `uses` beside it: a hostile file must not take a square of its lines
        while end < min(len(lines), at + 400) and (not lines[end].strip() or indent_of(lines[end]) > floor):
            if indent_of(lines[end]) == indent and STEP_USES.match(lines[end]) and not m.group(2):
                break
            end += 1
        yield m.group(3), "\n".join(lines[start:end])


def key_values(text, key):
    """Every value of a mapping key, at any depth, with the lines of its block."""
    lines, out = text.split("\n"), []
    for i, line in enumerate(lines):
        m = KEY_LINE.match(line)
        if not m or m.group(1) != key:
            continue
        column = len(line) - len(line.lstrip(" \t-")) if line.lstrip().startswith("-") else indent_of(line)
        block = [(m.group(2) or "").strip()]
        for j in range(i + 1, len(lines)):
            if lines[j].strip() and indent_of(lines[j]) <= column:
                break
            block.append(lines[j].strip())
        out.append("\n".join(block))
    return out


def not_commands(text):
    """A workflow's lines that are neither a command (scan.workflow_commands) nor a name: where a runner's label is set."""
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if m := COMMAND_KEY.match(line):
            if m.group(2).strip() and not m.group(2).strip().startswith(("|", ">")):
                continue
            while i < len(lines) and (not lines[i].strip() or indent_of(lines[i]) > len(m.group(1))):
                i += 1
        elif not re.match(r"^[ \t]*(?:-[ \t]+)?name[ \t]*:", line):
            out.append(line)
    return "\n".join(out)


def read_pkg_ops(pkg):
    """What the root package.json (parsed) names of the practices of Issue #1: the keys of fingerprints.PKG_OPS."""
    if not isinstance(pkg, dict):
        return []
    deps = {}
    for field in ("dependencies", "devDependencies"):
        if isinstance(pkg.get(field), dict):
            deps.update(pkg[field])

    def has(dotted):
        node = pkg
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return True

    return sorted(k for k, (keys, names) in fp.PKG_OPS.items() if any(map(has, keys)) or any(n in deps for n in names))


# The keys of ops.ci read from a workflow's shape rather than by a rule of fingerprints.OPS_RUN or OPS_TEXT.
OPS_SHAPE = (
    "merge_group",
    "release_trigger",
    "paths_trigger",
    "matrix",
    "multi_os",
    "multi_os_any",
    "services",
    "environment",
)


def read_ops(workflows, scripts=None, pkg=None):
    """The practices of Issue #1 that the workflows of one snapshot and its root package.json show:
    {"ci": the keys of the workflows, "pkg": the keys of the package.json}. A snapshot scanned before 2026-11-24
    has no "ops": not read, which is not the same as none.

    `workflows` are lowercased texts, `scripts` the root package.json's scripts (lowercased), `pkg` its parsed content.
    """
    found = set()
    for text in (drop_comments(t.replace("\r", "")) for t in workflows):
        run = workflow_commands(text)
        # the command a changesets step publishes with is an input of its own
        run += "".join("\n" + v for v in re.findall(r"^[ \t]*(?:-[ \t]+)?publish[ \t]*:[ \t]*(\S[^\n]*)$", text, re.M))
        run = re.sub(r"[ \t]*\\[ \t]*\n[ \t]*", " ", with_scripts(run, scripts or {}))  # a command continued over lines
        run = fp.ECHOED.sub("echo", run)  # what is printed is not run
        found |= {k for k, rx in fp.OPS_RUN.items() if rx.search(run)}
        found |= {k for k, rx in fp.OPS_TEXT.items() if rx.search(text)}
        events = triggers(text)
        if "merge_group" in events:
            found.add("merge_group")
        if "release" in events:
            found.add("release_trigger")
        if any(
            re.search(r"(?:^|[{,\s])paths(?:-ignore)?[\"']?[ \t]*:", events.get(e, ""), re.M)
            for e in ("push", "pull_request", "pull_request_target")
        ):
            found.add("paths_trigger")
        for job in job_keys(text):
            runner = "\n".join(job.get("runs-on", []) + job.get("strategy", []))
            if fp.OS_LABEL.search(runner):
                found.add("multi_os")
            if re.search(r"(?:^|[{,\s])matrix[ \t]*:", "\n".join(job.get("strategy", [])), re.M):
                found.add("matrix")
            if "services" in job:
                found.add("services")
            if any(job.get("environment", [])):
                found.add("environment")
        if fp.OS_LABEL.search(not_commands(text)):
            found.add("multi_os_any")
        for action, step in steps_using(text):
            if fp.SETUP_ACTION.match(action) and fp.SETUP_CACHE.search(step):
                found.add("cache")
            if fp.BUILD_PUSH_ACTION.match(action) and fp.PUSH_INPUT.search(step):
                found.add("image_push")
            if any(rx.match(action) and fp.DEPLOY_STEP[rx].search(step) for rx in fp.DEPLOY_STEP):
                found |= {"deploy", "deploy_other"}
        if any(rx.search(v) for key, rx in fp.PLATFORMS_ARM.items() for v in key_values(text, key)):
            found.add("multi_arch")
    return {"ci": sorted(found), "pkg": read_pkg_ops(pkg)}


def read_guards(tree, blobs, owner=""):
    """The checks and the security signals of one snapshot, from the contents of its small files.

    `owner` is the repo's account, lowercased: its own actions are not counted as a third party's.
    """
    text = collections.defaultdict(str)  # file kind -> lowercased text
    workflows, says, hooks, perms, codex = [], "", {"checks": set(), "guard": 0, "setup": 0, "other": 0}, None, None
    scripts, paths, pkg = {}, [], None
    for oid in tree["said"]:
        if oid in blobs:
            says += blobs[oid].decode(errors="replace") + "\n"
    for rule, path, oid, _ in tree["blobs"]:
        raw = blobs.get(oid)
        if raw is None:
            continue
        low = raw.decode(errors="replace").lower()
        if rule == "workflows":
            workflows.append(low)
            paths.append(path.lower())
        elif rule == "pkg_files":
            text[path.lower()] += low + "\n"
            if path.lower() == "package.json":
                found = pkg = loads_lenient(raw)
                found = found.get("scripts") if isinstance(found, dict) else None
                scripts = {str(k).lower(): str(v).lower() for k, v in found.items()} if isinstance(found, dict) else {}
        elif rule == "pkg_nested":  # a nested settings file is read with the root one of its name
            text[path.lower().rpartition("/")[2]] += low + "\n"
        elif rule == "git_hooks":
            text[rule] += fp.HOOK_NOISE.sub(" ", low) + "\n"
        elif rule in ("dependabot", "renovate", "security_md"):
            text[rule] += low + "\n"
        elif rule == "hooks_files":
            read_hooks(loads_lenient(raw), hooks)
        elif rule == "shared_settings" and path.endswith(".claude/settings.json"):
            cfg = loads_lenient(raw)
            if isinstance(cfg, dict):
                read_hooks(cfg, hooks)
                if perms is None or path == ".claude/settings.json":  # the root file wins, as in read_content
                    perms = read_permissions(cfg)
        elif rule == "shared_settings" and path == ".codex/config.toml":
            found = dict(re.findall(r"^\s*(sandbox_mode|approval_policy)\s*=\s*\"([^\"]+)\"", low, re.M))
            codex = {
                "sandbox": found.get("sandbox_mode"),
                "approval": found.get("approval_policy"),
                "writable": "[sandbox_workspace_write]" in low,
            }
    wf = read_workflows(workflows, owner, scripts)
    supply = read_supply(list(zip(paths, workflows)), scripts)
    manager = fp.PACKAGE_MANAGER.search(text["package.json"])
    any_hook = hooks["checks"] or hooks["guard"] or hooks["setup"] or hooks["other"]
    return {
        "checks": {
            "ci": wf["ci"],
            "tools": sorted(
                {k for k, rx in fp.PACKAGE_TOOLS.items() if rx.search(text["package.json"])}
                | {k for k, rx in fp.PYPROJECT_TOOLS.items() if rx.search(text["pyproject.toml"])}
            ),
            "hooks": dict(hooks, checks=sorted(hooks["checks"])) if any_hook else None,
            "git": sorted(k for k, rx in fp.GIT_HOOK_JOBS.items() if rx.search(text["git_hooks"])),
            "says": fp.instructions_say(says),
            "code": tree["code"],
        },
        "sec": {
            "scanners": wf["scanners"],
            "pins": wf["pins"],
            "agent": wf["agent"],
            "cooldown": sorted(
                k for k, files in fp.COOLDOWN.items() if any(rx.search(text[f]) for f, rx in files.items())
            ),
            "pm": sorted(
                k for k, files in fp.PACKAGE_GUARDS.items() if any(rx.search(text[f]) for f, rx in files.items())
            ),
            "perms": perms,
            "codex": codex,
            "policy_ai": bool(fp.SECURITY_POLICY_AI.search(text["security_md"])),
            # the package manager the root package.json pins: [name, major, minor]
            "manager": [manager.group(1), int(manager.group(2)), int(manager.group(3))] if manager else None,
            # security as a whole: what the workflows do to the supply chain,
            # [YAML workflows, those that scope their token], [checkout steps, those that keep the token off disk]
            **supply,
        },
        # the practices of Issue #1 that the workflows and the root package.json show
        "ops": read_ops(workflows, scripts, pkg),
    }


def wanted_blobs(picked, trees):
    """The blobs to fetch, in the order the cap keeps them: the newest snapshots first, and the
    content rules (workflows, settings, MCP configs) before what the guards add."""
    wanted = collections.OrderedDict()
    for p in reversed(picked):
        for rule, path, oid, _ in trees[p[1]]["blobs"] if p else []:
            if rule in CONTENT_RULES or p is picked[-1]:
                wanted[oid] = None
    for p in reversed(picked):
        for rule, path, oid, _ in trees[p[1]]["blobs"] if p else []:
            if rule in GUARD_RULES or rule == "hooks_files":
                wanted[oid] = None
        for oid in trees[p[1]]["said"] if p else []:
            wanted[oid] = None
    return list(wanted)


def read_commits(repo, dates):
    """Agent signatures on commits: a window of COMMIT_DAYS days behind each snapshot, plus discovery data."""
    # A commit's message is the repo owner's text, and git writes it as it is: any byte but NUL, which git stops a message
    # at. So the records end on NUL (-z), the body is the last field and may hold SEP, and a record whose timestamp is not
    # a number is not a commit: skipped. With any other separator, a body could stop the scan (a timestamp that does not
    # parse) or add a commit of its own, with any date and any signature.
    fmt = SEP.join(["%ct", "%an <%ae>", "%(trailers:key=Co-authored-by,valueonly=true,separator=%x1d)", "%b"])
    out = git(repo, "log", "-z", "--no-merges", "--since=" + SHALLOW_SINCE, "--format=" + fmt, "HEAD")
    commits, models, bots = [], collections.Counter(), collections.Counter()
    for rec in out.decode(errors="replace").split("\0"):
        parts = rec.lstrip("\n").split(SEP, 3)
        if len(parts) < 4 or not re.fullmatch(r"\d+", parts[0]):
            continue
        ts, author, coauthors, body = int(parts[0]), parts[1].lower(), parts[2].lower(), parts[3].lower()
        idents = [author] + [c.strip() for c in coauthors.split("\x1d") if c.strip()]
        agents = set()
        for ident in idents:
            agents.update(k for k, rx in fp.COMMIT_IDENTITY.items() if rx.search(ident))
            kept = fp.discovery_identity(ident)
            if kept:
                bots[kept] += 1
                if "noreply@anthropic.com" in ident:
                    month = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m")
                    models[month + " " + (fp.agent_name(ident.split("<")[0].strip()) or "claude")] += 1
        agents.update(k for k, rx in fp.COMMIT_BODY.items() if rx.search(body))
        commits.append((ts, agents))
    windows = []
    for d in dates:
        hi = end_of_day_ts(d)
        lo = hi - COMMIT_DAYS * 86400
        by, total, signed = collections.Counter(), 0, 0
        for ts, agents in commits:
            if lo < ts <= hi:
                total += 1
                signed += bool(agents)
                by.update(agents)
        windows.append({"total": total, "signed": signed, "by": dict(by)})
    return windows, dict(models), dict(bots.most_common(40))


def inside(path, target):
    """A target the repo writes in the file at `path` (a symlink's target, an imported file), as written, when it is relative
    and stays inside the repo; else None. An absolute one, or one that climbs out, can name a person's home folder."""
    if not target or target.startswith(("/", "~")) or "\\" in target or re.match(r"[A-Za-z]:", target):
        return None
    joined = os.path.normpath(os.path.join(os.path.dirname(path), target))
    return None if joined == ".." or joined.startswith(("../", "/")) else target


def store_instructions(name, head, blobs):
    """Keep the instruction files of the tip on disk (for later reading) and describe them."""
    out_dir = DATA / "raw" / "instructions" / slug(name)
    shutil.rmtree(out_dir, ignore_errors=True)
    files = [b for b in head["blobs"] if b[0] in fp.INSTRUCTION_RULES]
    files.sort(key=lambda b: (b[1].count("/"), b[1]))
    described = []
    for rule, path, oid, symlink in files[:MAX_INSTRUCTION_FILES]:
        raw = blobs.get(oid)
        if raw is None:
            continue
        text = raw.decode(errors="replace")
        info = {"rule": rule, "path": path, "bytes": len(raw), "lines": text.count("\n") + 1}
        if symlink:  # a target only inside the repo (inside()), else null
            info["symlink_to"] = inside(path, text.strip()) if len(text.strip()) <= 200 else None
        else:
            # A file that only points at another one ("@AGENTS.md") is a sync, not content.
            body = [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
            # an import is kept only inside the repo (inside()): an absolute one can name a person's home folder
            info["imports"] = sorted({m for l in body for m in re.findall(r"@([\w./-]+\.md)\b", l) if inside(path, m)})[
                :10
            ]
            info["pointer_only"] = len(raw) < 400 and bool(re.search(r"@[\w./-]+\.md|\b(?:AGENTS|CLAUDE)\.md\b", text))
            if len(raw) <= MAX_STORED_BYTES:
                out_dir.mkdir(parents=True, exist_ok=True)
                # Named by a hash of its path, which the scan stores beside it: a path flattened into one name could pass the
                # file system's 255 bytes or collide on a disk that ignores case (CLAUDE.md, claude.md).
                info["stored"] = hashlib.sha256(path.encode()).hexdigest()[:24] + ".md"
                (out_dir / info["stored"]).write_bytes(raw)
        described.append(info)
    return described


def scan(repo_info, keep=False):
    name = repo_info["name"]
    out_path = DATA / "scan" / (slug(name) + ".json")
    if out_path.exists():
        return name, "cached", 0
    while shutil.disk_usage(str(CLONES)).free < MIN_FREE_GB * 2**30:
        time.sleep(30)  # other clones are being deleted as they finish
    t0 = time.time()
    repo = CLONES / slug(name)
    shutil.rmtree(repo, ignore_errors=True)
    try:
        mode = clone(name, repo)
        dates = snapshot_dates()
        picked, tip = pick_commits(repo, dates, repo_info["created_at"], mode)
        trees = {}
        for p in picked:
            if p and p[1] not in trees:
                trees[p[1]] = read_tree(repo, p[0])
        head = trees[picked[-1][1]]

        blobs = fetch_blobs(repo, wanted_blobs(picked, trees)[:MAX_BLOBS])
        windows, models, bots = read_commits(repo, dates)

        sets, set_index, snaps = [], {}, []
        for d, p, window in zip(dates, picked, windows):
            if not p:
                snaps.append(None)
                continue
            tree = trees[p[1]]
            key = json.dumps([tree["hits"], tree["root"]], sort_keys=True)
            if key not in set_index:
                set_index[key] = len(sets)
                sets.append({"hits": tree["hits"], "root": tree["root"], "n_files": tree["n_files"]})
            # "files" is this snapshot's own file count; a set keeps the count of the first snapshot it served
            snap = {
                "date": d.isoformat(),
                "sha": p[0],
                "approx": p[2],
                "set": set_index[key],
                "commits90": window,
                "files": tree["n_files"],
            }
            snap.update(read_content(tree, blobs))
            snap.update(read_guards(tree, blobs, name.split("/")[0].lower()))
            snaps.append(snap)

        clone_mb = sum(f.stat().st_size for f in repo.rglob("*") if f.is_file()) // 2**20
        write_json(
            out_path,
            {
                "name": name,
                "league": repo_info["league"],
                "as_of": AS_OF.isoformat(),
                "history": mode,
                "tip_ts": tip[2],
                "clone_mb": clone_mb,
                "since": SHALLOW_SINCE,  # where the clone and the commit windows start (common.py); a scan without it: OLD_SINCE
                "snaps": snaps,
                "sets": sets,
                "head_paths": head_paths(head["paths"]),
                # where linked agent directories point, to count what they hold: a target only inside the repo (inside()), else null
                "links": [
                    {"path": path, "to": inside(path, to) if len(to) <= 300 else None}
                    for rule, path, oid, _ in head["blobs"]
                    if rule == "link" and oid in blobs
                    for to in [blobs[oid].decode(errors="replace").strip()]
                ],
                "instructions": store_instructions(name, head, blobs),
                "models": models,
                "bots": bots,
            },
        )
        return name, "ok %s %dMB" % (mode, clone_mb), time.time() - t0
    except Exception as e:  # one bad repo must not stop the batch
        return name, "FAILED %s" % str(e)[:200], time.time() - t0
    finally:
        if not keep:
            shutil.rmtree(repo, ignore_errors=True)


def reread(repo_info, keep=False):
    """Read again the commits an earlier scan read, with the rules as they are now.

    A new rule needs the trees again, and a new scan would pick today's commits and move every
    published figure. This keeps the snapshots of the stored scan (same commits, so same trees),
    reads their fingerprints and their guard signals again, and leaves the rest as it was written:
    commit windows, models, bots, instruction files, and the content signals of the first scan.
    The status names the rules whose hits changed, which should be the new ones only.
    """
    name = repo_info["name"]
    out_path = DATA / "scan" / (slug(name) + ".json")
    if not out_path.exists():
        return name, "no scan to read again", 0
    old = read_json(out_path)
    t0 = time.time()
    repo = CLONES / slug(name)
    try:
        if not (repo / ".git").exists():  # a clone kept by an earlier run is used as it is
            shutil.rmtree(repo, ignore_errors=True)
            clone(name, repo)
        shas = sorted({snap["sha"] for snap in old["snaps"] if snap})
        check = run(["git", "-C", str(repo), "cat-file", "--batch-check"], data=("\n".join(shas) + "\n").encode())
        missing = [line.split()[0] for line in check.stdout.decode().splitlines() if line.endswith("missing")]
        if missing:
            raise RuntimeError("%d of %d snapshot commits are gone from the repo" % (len(missing), len(shas)))
        trees = {sha: read_tree(repo, sha) for sha in shas}
        picked = [(snap["sha"], snap["sha"], snap["approx"]) if snap else None for snap in old["snaps"]]
        wanted = wanted_blobs(picked, trees)
        blobs = fetch_blobs(repo, wanted[:MAX_BLOBS])

        sets, set_index, snaps, changed, content = [], {}, [], set(), 0
        for snap in old["snaps"]:
            if not snap:
                snaps.append(None)
                continue
            tree, before = trees[snap["sha"]], old["sets"][snap["set"]]
            if tree["root"] != before["root"]:
                raise RuntimeError("the root of %s is not the one the scan read" % snap["sha"][:10])
            changed |= {
                rule
                for rule in set(tree["hits"]) | set(before["hits"])
                if tree["hits"].get(rule) != before["hits"].get(rule)
            }
            content += any(snap[k] != v for k, v in read_content(tree, blobs).items())
            # The file count a set carries is published (the size slices): each snapshot keeps the one
            # it had, so more rules, which split the sets, move no figure. Its own count goes in "files".
            key = json.dumps([tree["hits"], tree["root"], before["n_files"]], sort_keys=True)
            if key not in set_index:
                set_index[key] = len(sets)
                sets.append({"hits": tree["hits"], "root": tree["root"], "n_files": before["n_files"]})
            snaps.append(
                dict(
                    snap,
                    set=set_index[key],
                    files=tree["n_files"],
                    **read_guards(tree, blobs, name.split("/")[0].lower()),
                )
            )
        head = trees[old["snaps"][-1]["sha"]]
        write_json(out_path, dict(old, snaps=snaps, sets=sets, head_paths=head_paths(head["paths"])))
        return (
            name,
            "read again; rules that changed: %s%s%s"
            % (
                " ".join(sorted(changed)) or "none",
                "; %d snapshots whose first content signals read differently (kept as scanned)" % content
                if content
                else "",
                "; %d blobs over the cap" % (len(wanted) - MAX_BLOBS) if len(wanted) > MAX_BLOBS else "",
            ),
            time.time() - t0,
        )
    except Exception as e:  # one bad repo must not stop the batch
        return name, "FAILED %s" % str(e)[:200], time.time() - t0
    finally:
        if not keep:
            shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("panel")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only")
    ap.add_argument("--skip", default="", help="comma-separated repos to leave out")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--reread", action="store_true", help="read the stored snapshots again with today's rules")
    a = ap.parse_args()
    repos = [
        r for r in read_json(a.panel) if (not a.only or r["name"] == a.only) and r["name"] not in a.skip.split(",")
    ]
    CLONES.mkdir(parents=True, exist_ok=True)
    # A scan waits on the network, so threads do. A re-read matches trees it already has: processes.
    with (ProcessPoolExecutor if a.reread else ThreadPoolExecutor)(a.jobs) as pool:
        jobs = [pool.submit(reread if a.reread else scan, r, a.keep) for r in repos]
        for i, job in enumerate(as_completed(jobs), 1):
            print("[%d/%d] %s: %s (%.0fs)" % ((i, len(repos)) + job.result()), flush=True)
