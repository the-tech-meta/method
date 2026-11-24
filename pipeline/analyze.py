"""Turn the per-repo scans into the numbers and sentences the page shows: data/meta.json.

Reads the two panels (data/panel_pro.json, data/panel_ladder.json), one scan per repo (data/scan/), one file of API
signals per repo (data/api/), the rule both panels were built by (data/panel_rule.json) and the ROSS Index
(data/ross_index.json). A repo without both a scan and an API file is skipped. Writes data/meta.json, which the page
reads whole: every figure, and the sentences that quote them.

  analyze.py            write data/meta.json
  analyze.py --audit    also print what each fingerprint matched, to check the rules by eye
  analyze.py --matrix   also print the pro scene repo by repo, to design the builds

Every practice is a yes/no question asked of a repo at a date (a monthly snapshot, common.snapshot_dates). Adoption is
the share of repos answering yes, per league, with a Wilson 95% interval. The panels are fixed: today's repos at every
date, a repo counting as without a practice before it existed.
"""

import argparse
import collections
import datetime as dt
import math
import os
import re
import statistics
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fingerprints as fp
from common import (
    AS_OF,
    COMMIT_DAYS,
    DATA,
    ISSUE_DATE,
    ISSUE_N,
    LATEST_ITEMS,
    OLD_SINCE,
    end_of_day_ts,
    read_json,
    slug,
    snapshot_dates,
    write_json,
)
import panel  # the owners left out by the rule (condition 7), each with its tie: said on the Method tab

MIN_SIGNED_COMMITS = 3  # agent-signed commits in the last COMMIT_DAYS days to count as a habit, not a trial
MIN_AGENT_PRS = 2  # of the latest LATEST_ITEMS pull requests
MIN_REVIEW_COMMENTS = 3  # from AI reviewers, among the latest LATEST_ITEMS review or PR comments
# from one security bot, or one host's preview bot, among the latest LATEST_ITEMS review or PR comments, as for an AI reviewer
MIN_BOT_COMMENTS = 2
BACK = 3  # snapshots (months) between "then" and now; the page reads it from meta.json ("back")
# The least base of a percentage or a bar, in repos: on a base of one repo, a share reads "100% · 1 repo". Under it
# the page writes the count, "1 of 1", and draws neither a percentage nor a bar; a context slice under it is hidden.
# The page reads it from meta.json.
MIN_BASE = 20
# "The pro rate is N× the ladder's" is shown only when this many repos of each league have the practice: on fewer, a
# repo more or less swings it (on the run of 2026-11-21, Agent in CI read 74× on one ladder repo). Under it the page
# gives the two counts.
MIN_LEAD = 10
# A lead under this many times is given to one decimal ("4.3×"), from it as a whole number ("15×"); the Method tab says it.
LEAD_WHOLE = 10

# Bots that review code with a model, matched as a prefix of the lowercased login.
AI_REVIEWERS = (
    "coderabbitai",
    "copilot",
    "cursor",
    "greptile",
    "claude",
    "chatgpt-codex-connector",
    "gemini-code-assist",
    "graphite-app",
    "ellipsis-dev",
    "sourcery-ai",
    "qodo-",
    "codiumai-pr-agent",
    "devin-ai-integration",
    "macroscope",
    "korbit-ai",
    "seer-by-sentry",
    "cubic-dev-ai",
    "bito-code-review",
    "augment",
    "kilo-code",
    "charliecreates",
    "veria-ai",
    "capy-ai",
    "robin-agent",
    "corridor-security",
    "pullfrog",
    "hacktron-app",
    "strix-security",
    "superagent-security",
    "parameterai",
    "stilla",
)
# Company-built and long-tail reviewers: accepted on their name, and only when they leave
# inline review comments. vercel[bot] also posts deployment links, so it is inline-only too.
AI_REVIEWER_NAME = re.compile(r"(?:^|-)ai(?:-|\[|$)|agent|review|bonk|warden|junior|clank|^vercel\[bot\]$")
NOT_REVIEWERS = ("github-advanced-security", "github-code-quality", "github-actions", "renovate")

# ---------- The list of practices: what the pro scene does -----------------------------------------------------------
# The bar: a candidate is on the page when it is on (below) and this share of the pro scene or more has it at the last snapshot, its
# count compared exactly (11 of 209 passes, 10 does not). A candidate under it is still counted, and listed in meta.json's
# `under_bar` with why; it comes on the day it crosses. The ladder takes no part in the choice. The page reads it from meta.json.
BAR = 0.05
# Every candidate, one line each, with its three switches: its field (the section of Practices it is in: build, checks, security,
# ship), its kind ("agent", made for coding agents; "any", not specific to AI) and whether it is on. Changing one is a one-line edit
# here, then analyze.py: the sections, the map, What moved, What left, What stayed, Every number, the tags and the counts follow.
# How each is read is apart: ITEMS (the tree, the commits, the API, over every repo; TRACES for the unions of traces) and LENS_ITEMS
# (the lens read of a snapshot, over the repos read for it).
PRACTICES = {
    # Build
    "instructions": ("build", "agent", True),
    "multi_tool": ("build", "agent", True),
    "scoped_instructions": ("build", "agent", True),
    "agents_md": ("build", "agent", True),
    "claude_md": ("build", "agent", True),
    "agents_dir": ("build", "agent", True),
    "ai_docs": ("build", "agent", True),
    "memory": ("build", "agent", True),
    "skills": ("build", "agent", True),
    "commands": ("build", "agent", True),
    "subagents": ("build", "agent", True),
    "mcp": ("build", "agent", True),
    "hooks": ("build", "agent", True),
    "shared_settings": ("build", "agent", True),
    "spec_framework": ("build", "agent", True),
    "plans": ("build", "agent", True),
    "task_tracker": ("build", "agent", True),
    "adr": ("build", "any", True),
    "agent_in_ci": ("build", "agent", True),
    "cloud_env": ("build", "agent", True),
    "parallel_setup": ("build", "agent", True),
    "agent_commits": ("build", "agent", True),
    "agent_prs": ("build", "agent", True),
    "ai_policy": ("build", "agent", True),
    "issue_forms": ("build", "any", True),
    "pr_template": ("build", "any", True),
    "toolchain_pinned": ("build", "any", True),
    "compose_dev": ("build", "any", True),
    "task_runner": ("build", "any", True),
    "editor_settings": ("build", "any", True),
    "env_example": ("build", "any", True),
    "stale_bot": ("build", "any", True),
    "dev_env_declared": ("build", "any", True),
    "patched_deps": ("build", "any", True),
    "auto_label": ("build", "any", True),
    # Test
    # AI review is a check, not a part of Build: reviewing a change is checking it before it lands
    "ai_review": ("checks", "agent", True),
    "ai_review_config": ("checks", "agent", True),
    "says_tests": ("checks", "agent", True),
    "checks_ext": ("checks", "agent", True),
    "hook_checks": ("checks", "agent", True),
    "fast_lint": ("checks", "any", True),
    "custom_lint": ("checks", "any", True),
    "knip": ("checks", "any", True),
    "git_hooks": ("checks", "any", True),
    "ci_tests": ("checks", "any", True),
    "ci_lint": ("checks", "any", True),
    "ci_types": ("checks", "any", True),
    "ci_concurrency": ("checks", "any", True),
    "ci_timeouts": ("checks", "any", True),
    "formatter_config": ("checks", "any", True),
    "ci_cache": ("checks", "any", True),
    "ci_multi_os": ("checks", "any", True),
    "e2e_browser": ("checks", "any", True),
    "coverage": ("checks", "any", True),
    "ci_path_filters": ("checks", "any", True),
    "ci_services": ("checks", "any", True),
    "merge_queue": ("checks", "any", True),
    "spellcheck": ("checks", "any", True),
    "actionlint": ("checks", "any", True),
    # off: the key says jobs are repeated, not over what (CI on Windows or macOS reads it)
    "ci_matrix": ("checks", "any", False),
    "lint_staged": ("checks", "any", False),  # a variant of Git hooks, and one JavaScript tool's trace
    # Secure
    "kept_from_agent": ("security", "agent", True),
    "says_security": ("security", "agent", True),
    "perm_rules": ("security", "agent", True),
    "guard_hook": ("security", "agent", True),
    "security_ext": ("security", "agent", True),
    "fence_tools": ("security", "agent", True),
    "pinned": ("security", "any", True),
    "zizmor": ("security", "any", True),
    "token_scoped": ("security", "any", True),
    "checkout_no_token": ("security", "any", True),
    "signed_builds": ("security", "any", True),
    "sbom": ("security", "any", True),
    "threat_model": ("security", "any", True),
    "cooldown": ("security", "any", True),
    "code_scan": ("security", "any", True),
    "dep_bot": ("security", "any", True),
    "security_md": ("security", "any", True),
    "codeowners": ("security", "any", True),
    "dep_audit_ci": ("security", "any", True),
    "fuzz_tests": ("security", "any", True),
    "secret_scan_ci": ("security", "any", True),
    "branch_protected": ("security", "any", True),
    "pr_required": ("security", "any", True),
    "private_reporting": ("security", "any", True),
    "sec_bots": ("security", "any", True),
    "app_token": ("security", "any", True),
    # Ship
    "release_automation": ("ship", "any", True),
    "container_images": ("ship", "any", True),
    "multi_arch_images": ("ship", "any", True),
    "environments": ("ship", "any", True),
    "deploy_cloud": ("ship", "any", True),
    "publish_package": ("ship", "any", True),
    "changelog": ("ship", "any", True),
    "docs_site": ("ship", "any", True),
    "change_convention": ("ship", "any", True),  # the convention exists to derive versions and release notes
    "changesets": ("ship", "any", True),
    "preview_deploys": ("ship", "any", True),
}
FIELD_IDS = ("build", "checks", "security", "ship")
KINDS = ("agent", "any")


def passes_bar(k, n):
    """Whether k repos of n are BAR of them or more, compared exactly: 11 of 209 passes, 10 does not (no float edge)."""
    return n > 0 and Fraction(k, n) >= Fraction(str(BAR))


# How each practice that is a union of traces is read: a repo has it at a snapshot when any one of its traces is there.
# "rule:x" is a path rule of the scan (fingerprints.py), counted as every path rule is (count(), still_valid); "ci:x" and "pkg:x" are
# keys of the snapshot's `ops` (what its workflows and its root package.json show); "sec:x" a field of the snapshot's `sec`. Traces
# joined by "+" are one trace that needs all of them at the snapshot. A snapshot read before the scan read a trace has none of it:
# absent is not read, so without.
TRACES = {
    "issue_forms": ("rule:issue_templates",),
    "pr_template": ("rule:pr_template",),
    # the version files of other languages (Go, Java, Bun, SDKMAN, proto) count too: fairness across languages
    "toolchain_pinned": ("rule:toolchain_files", "rule:toolchain_other", "sec:manager"),
    "compose_dev": ("rule:compose",),
    "task_runner": ("rule:task_runner",),
    "editor_settings": ("rule:editorconfig", "rule:editor_settings"),
    "env_example": ("rule:env_example",),
    "stale_bot": ("ci:stale", "rule:stale_config"),
    "dev_env_declared": ("rule:devcontainer", "rule:nix_env"),
    "patched_deps": ("rule:patches", "pkg:patches"),
    "auto_label": ("ci:labeler", "rule:labeler_config"),
    "ci_concurrency": ("ci:concurrency",),
    "ci_timeouts": ("ci:timeouts",),
    "formatter_config": ("rule:formatter_config", "rule:formatter_other", "pkg:prettier"),
    "ci_cache": ("ci:cache",),
    "ci_multi_os": ("ci:multi_os",),
    "e2e_browser": ("rule:playwright", "rule:cypress"),
    "coverage": ("rule:coverage_config", "rule:coverage_other", "ci:coverage"),
    "ci_path_filters": ("ci:paths_trigger", "ci:paths_action", "ci:affected"),
    "ci_services": ("ci:services",),
    "merge_queue": ("ci:merge_group",),
    "spellcheck": ("rule:spellcheck_config", "ci:spellcheck"),
    "actionlint": ("rule:actionlint_config", "ci:actionlint"),
    "ci_matrix": ("ci:matrix",),
    "lint_staged": ("rule:lint_staged_config", "pkg:lint_staged"),
    "app_token": ("ci:app_token",),
    "release_automation": ("ci:release",),
    "container_images": ("ci:image_push",),
    # an ARM build in a workflow that builds an image: setup-qemu or an arm64 platform alone also builds desktop apps and binaries
    "multi_arch_images": ("ci:multi_arch+ci:image_build",),
    "environments": ("ci:environment",),
    # not `aws s3 sync` alone (deploy_s3): a copy of docs, release files or test reports as often as the product
    "deploy_cloud": ("ci:deploy_other", "ci:deploy_k8s"),
    "publish_package": ("ci:publish",),
    "changelog": ("rule:changelog",),
    # Mintlify's docs.json (every match of the pro scene read on 2026-11-24 was Mintlify's) and the docs tools of other languages
    "docs_site": ("rule:docs_site", "rule:docs_json", "rule:docs_other"),
    "change_convention": ("rule:commit_convention", "pkg:commitlint", "ci:title_check"),
    # Changesets, or a folder of one note per change (towncrier, changie and the like): one practice in several ecosystems
    "changesets": ("rule:changesets", "rule:changelog_dir"),
}
# Preview deployments, read only from recent pull request comments: the bot of one host with MIN_BOT_COMMENTS comments
# or more among a repo's latest LATEST_ITEMS review and pull request comments (the logins as the API files hold them). A
# preview bot is not an AI reviewer here: vercel[bot] is matched by AI_REVIEWER_NAME too, and the AI reviewers' count
# does not change.
PREVIEW_BOTS = {
    "vercel[bot]": "Vercel",
    "netlify[bot]": "Netlify",
    "cloudflare-workers-and-pages[bot]": "Cloudflare",
    "railway-app[bot]": "Railway",
    "render[bot]": "Render",
}

# The practices read from the tree, the commits and the GitHub API, over every repo of a league (features(),
# api_features()): id, label, history (False = read from the GitHub API, today only), what we look for. Their field,
# kind and on are in PRACTICES.
ITEMS = [
    (
        "instructions",
        "Agent instruction file",
        True,
        "CLAUDE.md, AGENTS.md, .cursor/rules, copilot-instructions.md and the like",
    ),
    (
        "multi_tool",
        "Instructions for 2+ tools",
        True,
        "instruction files of at least two tool families in the same repo",
    ),
    (
        "scoped_instructions",
        "Per-package instructions",
        True,
        "a CLAUDE.md or AGENTS.md below the repo root",
    ),
    ("agents_md", "AGENTS.md", True, "an AGENTS.md file, at the root or in a package"),
    ("claude_md", "CLAUDE.md", True, "a CLAUDE.md file, at the root or in a package"),
    (
        "agents_dir",
        "Shared .agents/ directory",
        True,
        "a .agents/ directory at the root, read by several tools",
    ),
    ("ai_docs", "llms.txt", True, "llms.txt or llms-full.txt committed"),
    ("memory", "Agent memory in repo", True, "memory-bank/, .serena/, .claude/memory/, MEMORY.md"),
    (
        "skills",
        "Skills",
        True,
        "SKILL.md under .claude/skills, .agents/skills or another agent directory",
    ),
    (
        "commands",
        "Custom commands",
        True,
        ".claude/commands, .cursor/commands, .github/prompts, .codex/prompts",
    ),
    (
        "subagents",
        "Custom subagents",
        True,
        ".claude/agents, .github/agents, .cursor/agents, .codex/agents",
    ),
    ("mcp", "MCP servers configured", True, ".mcp.json, .cursor/mcp.json, .vscode/mcp.json"),
    ("hooks", "Agent hooks", True, "hook scripts or a hooks block in committed agent settings"),
    (
        "shared_settings",
        "Shared agent settings",
        True,
        ".claude/settings.json, .codex/config.toml, opencode.json committed",
    ),
    (
        "spec_framework",
        "Spec framework",
        True,
        ".specify/ (spec-kit), openspec/, .kiro/specs/, BMAD, .agent-os/, .planning/",
    ),
    ("plans", "Plans committed", True, "plans/, docs/plans/, exec-plans/, PLAN.md"),
    ("task_tracker", "Agent task tracker", True, ".beads/, .taskmaster/, backlog/tasks/"),
    ("adr", "Decision records (ADR)", True, "docs/adr/, docs/decisions/. Not specific to AI"),
    ("agent_in_ci", "Agent in CI", True, "a coding agent called from a GitHub Actions workflow"),
    (
        "cloud_env",
        "Cloud agent environment",
        True,
        "copilot-setup-steps.yml, .cursor/environment.json, .codex/environments/",
    ),
    (
        "parallel_setup",
        "Parallel worktree setup",
        True,
        ".cursor/worktrees.json, .worktreeinclude, conductor.json, .superset/",
    ),
    (
        "agent_commits",
        "Agent-signed commits",
        True,
        "%d or more commits in the last %d days carrying an agent signature" % (MIN_SIGNED_COMMITS, COMMIT_DAYS),
    ),
    (
        "agent_prs",
        "Agent-opened pull requests",
        False,
        "%d or more of the latest %d pull requests opened by an agent" % (MIN_AGENT_PRS, LATEST_ITEMS),
    ),
    (
        "ai_review",
        "AI review on pull requests",
        False,
        "%d or more of the latest %d review or pull request comments left by AI reviewer bots"
        % (MIN_REVIEW_COMMENTS, LATEST_ITEMS),
    ),
    (
        "ai_review_config",
        "AI review configured",
        True,
        ".coderabbit.yaml, BUGBOT.md, greptile.json, REVIEW.md",
    ),
    ("ai_policy", "AI contribution policy", True, "AI_POLICY.md and similar"),
    # the practices read as unions of traces (TRACES)
    (
        "issue_forms",
        "Issue templates",
        True,
        "a file in .github/ISSUE_TEMPLATE/, or an ISSUE_TEMPLATE.md at the root, in .github/ or in docs/",
    ),
    (
        "pr_template",
        "Pull request template",
        True,
        "pull_request_template.md at the root, in .github/ or in docs/, or a PULL_REQUEST_TEMPLATE/ folder there",
    ),
    (
        "toolchain_pinned",
        "Toolchain pinned",
        True,
        ".nvmrc, .node-version, .python-version, .ruby-version, rust-toolchain, .tool-versions, a mise config, or the version "
        "file of Go, Java, Bun, SDKMAN or proto, at the root; or packageManager in the root package.json",
    ),
    (
        "compose_dev",
        "Docker Compose file",
        True,
        "compose.yml, docker-compose.yml and their variants, at the root or one or two folders down, outside shipped folders",
    ),
    ("task_runner", "Task runner", True, "a Makefile, GNUmakefile, justfile or Taskfile.yml at the root"),
    (
        "editor_settings",
        "Shared editor settings",
        True,
        ".editorconfig at the root, .vscode/settings.json or extensions.json, .zed/settings.json",
    ),
    (
        "env_example",
        "Example settings file",
        True,
        ".env.example, .env.sample, .env.template, .env.dist, example.env and the like, at the root or one or two folders "
        "down, outside shipped folders",
    ),
    ("stale_bot", "Stale bot", True, "actions/stale in a workflow, or .github/stale.yml"),
    (
        "dev_env_declared",
        "Dev environment as code",
        True,
        ".devcontainer/, or flake.nix, shell.nix, devbox.json, devenv.nix at the root",
    ),
    (
        "patched_deps",
        "Patched dependencies",
        True,
        "a .patch or .diff file in a root patches/ folder or in .yarn/patches/, or patch-package or patchedDependencies "
        "in the root package.json",
    ),
    ("auto_label", "Labels by path", True, "actions/labeler in a workflow, or .github/labeler.yml"),
    (
        "ci_concurrency",
        "Stale CI runs cancelled",
        True,
        "a workflow with cancel-in-progress set to anything but false",
    ),
    (
        "ci_timeouts",
        "Time limits on CI jobs",
        True,
        "timeout-minutes in a workflow: one job or step is enough",
    ),
    (
        "formatter_config",
        "Formatter config",
        True,
        "a config of Prettier, Biome, Oxfmt, rustfmt, clang-format, dprint, Taplo, StyLua, SwiftFormat, scalafmt, "
        "ocamlformat, PHP CS Fixer, cljfmt, treefmt or yamlfmt, or .formatter.exs; prettier in the root package.json",
    ),
    (
        "ci_cache",
        "CI cache",
        True,
        "actions/cache and its restore and save, the rust-cache and sccache actions, or a cache input set on a setup action",
    ),
    ("ci_multi_os", "CI on Windows or macOS", True, "a windows- or macos- runner label in a workflow"),
    (
        "e2e_browser",
        "Browser end-to-end tests",
        True,
        "a Playwright or Cypress config, test folders included",
    ),
    (
        "coverage",
        "Test coverage measured",
        True,
        "a Codecov, Coveralls, coverage.py, nyc, c8, SimpleCov or tarpaulin config, a coverage upload action, or a coverage "
        "flag or tool in a workflow's commands",
    ),
    (
        "ci_path_filters",
        "CI filtered by changed files",
        True,
        "a paths or paths-ignore filter on one workflow's push or pull request trigger or more, the paths-filter or "
        "changed-files actions, nx affected or turbo --affected",
    ),
    ("ci_services", "Service containers in CI", True, "a services key on a workflow job"),
    ("merge_queue", "Merge queue", True, "a workflow triggered on merge_group"),
    (
        "spellcheck",
        "Spell check",
        True,
        "a typos, cspell or codespell config, or one of the three run by a workflow",
    ),
    ("actionlint", "Workflow lint", True, ".github/actionlint.yml, or actionlint run by a workflow"),
    ("ci_matrix", "CI matrix", True, "a strategy matrix on a workflow job"),
    (
        "lint_staged",
        "Git hooks on staged files",
        True,
        "a lint-staged config, or lint-staged in the root package.json",
    ),
    (
        "app_token",
        "GitHub App token in CI",
        True,
        "actions/create-github-app-token or the github-app-token action in a workflow",
    ),
    (
        "release_automation",
        "Releases cut by CI",
        True,
        "a workflow that creates a release: gh release create, the action-gh-release and release-action actions, "
        "GoReleaser, release-please, semantic-release, changesets/action. A workflow that only reacts to a release is not one",
    ),
    (
        "container_images",
        "Container images published by CI",
        True,
        "a workflow that pushes an image: docker push, --push on a buildx build or bake, docker buildx imagetools create, a "
        "build-push action whose push input is not false",
    ),
    (
        "multi_arch_images",
        "Multi-architecture images",
        True,
        "an image built in a workflow, and docker/setup-qemu-action, a platforms input or --platform flag naming arm64, or "
        "imagetools create, in a workflow",
    ),
    (
        "environments",
        "Environments for CI jobs",
        True,
        "an environment key on a workflow job. What the environment holds or requires is a setting, not read",
    ),
    (
        "deploy_cloud",
        "Deploys from CI",
        True,
        "a deploy command or action in a workflow: wrangler, flyctl, kubectl apply, helm upgrade, the AWS, Google Cloud, "
        "Vercel, Netlify and Firebase deploys, serverless, cdk, sst, terraform apply, pulumi up. Neither a cloud login nor a "
        "copy of files to S3 is one",
    ),
    (
        "publish_package",
        "Packages published by CI",
        True,
        "an npm, pnpm, yarn, bun, cargo, uv, poetry, twine, gem, dotnet nuget or lerna publish command, changeset publish, "
        "or the PyPI publish action, in a workflow",
    ),
    (
        "changelog",
        "Changelog",
        True,
        "CHANGELOG, CHANGES, HISTORY, NEWS or RELEASES (.md, .rst, .txt or none) at the root",
    ),
    (
        "docs_site",
        "Docs site in the repo",
        True,
        "a config of Mintlify, Docusaurus, MkDocs, Sphinx, Read the Docs, VitePress, TypeDoc, mdBook, Doxygen, DocFX, Antora, "
        "VuePress, Rspress or Jupyter Book, at the root or one or two folders down",
    ),
    (
        "change_convention",
        "Commit convention enforced",
        True,
        "a commitlint config, @commitlint/cli in the root package.json, or commitlint or the semantic-pull-request action "
        "in a workflow. A commitizen config alone checks nothing",
    ),
    (
        "changesets",
        "Change notes",
        True,
        ".changeset/config.json, or a folder of one note per change at the root: .changes/, changelog.d/, newsfragments/ "
        "and the like",
    ),
    (
        "preview_deploys",
        "Preview deployments",
        False,
        "%d or more comments from one host's preview bot (Vercel, Netlify, Railway, Render and the like) among the latest %d review "
        "and pull request comments" % (MIN_BOT_COMMENTS, LATEST_ITEMS),
    ),
]
LABEL = {i[0]: i[1] for i in ITEMS}
OFF_MAP = {"agents_md", "claude_md"}  # already covered by "Agent instruction file" on the map
NO_KEEP_RATE = {"ai_docs"}  # llms.txt moves to the docs build, which reads as a removal

# Tool footprints: root entries and instruction files that belong to one tool.
TOOLS = [
    ("claude", "Claude Code", {".claude"}, ("claude_md",)),
    ("cursor", "Cursor", {".cursor", ".cursorrules", ".cursorignore"}, ("cursor_rules",)),
    ("codex", "Codex", {".codex"}, ()),
    ("copilot", "GitHub Copilot", set(), ("copilot_instructions",)),
    ("gemini", "Gemini CLI", {".gemini"}, ("gemini_md",)),
    ("opencode", "opencode", {".opencode", "opencode.json", "opencode.jsonc"}, ()),
    ("windsurf", "Windsurf", {".windsurf", ".windsurfrules"}, ("windsurf_rules",)),
    ("cline", "Cline, Roo, Kilo", {".clinerules", ".roo", ".roomodes", ".kilocode"}, ("cline_roo_rules",)),
    ("kiro", "Kiro", {".kiro"}, ()),
    ("amp", "Amp", {".amp"}, ()),
    ("devin", "Devin", {".devin"}, ()),
    ("jules", "Jules", {".jules"}, ()),
]

BANDS = [
    {"from": 0, "to": 0.1, "label": "Rare, even among pros", "short": "Rare", "note": "Under 10% of the pro scene"},
    {
        "from": 0.1,
        "to": 0.5,
        "label": "Spreading among pros",
        "short": "Spreading",
        "note": "10% to half of the pro scene",
    },
    {
        "from": 0.5,
        "to": 1,
        "label": "Standard among pros",
        "short": "Standard",
        "note": "Half of the pro scene or more",
    },
]

# Releases marked on the film and on Build's timeline, to the month, with the page that dates each.
# The film's ticks take the month and the label; Build's timeline links each to its source.
EVENTS = [
    ("2025-02", "Claude Code preview", "https://www.anthropic.com/news/claude-3-7-sonnet"),
    ("2025-05", "Claude Code generally available", "https://www.anthropic.com/news/claude-4"),
    ("2025-08", "AGENTS.md published", "https://www.infoq.com/news/2025/08/agents-md/"),
    ("2025-10", "Agent Skills launch", "https://claude.com/blog/skills"),
    (
        "2025-12",
        "Skills become an open standard",
        "https://siliconangle.com/2025/12/18/anthropic-makes-agent-skills-open-standard/",
    ),
    (
        "2026-01",
        "Cursor adds a co-author trailer",
        "https://forum.cursor.com/t/co-author-added-without-consent-and-cant-be-turned-off/150096",
    ),
    (
        "2026-09",
        "Claude Code reads AGENTS.md",
        "https://www.infoworld.com/article/4224410/claude-code-now-also-accepts-instructions-in-openais-agents-md-format.html",
    ),
]

# Where a practice is read. Anything not listed is read from the file tree.
SEEN_IN = {
    "agent_commits": "commit history",
    "agent_in_ci": "workflow files",
    "agent_prs": "pull requests",
    "ai_review": "pull requests",
    "preview_deploys": "pull requests",
    "ci_concurrency": "workflow files",
    "ci_timeouts": "workflow files",
    "ci_cache": "workflow files",
    "ci_multi_os": "workflow files",
    "ci_path_filters": "workflow files",
    "ci_services": "workflow files",
    "merge_queue": "workflow files",
    "ci_matrix": "workflow files",
    "app_token": "workflow files",
    "release_automation": "workflow files",
    "container_images": "workflow files",
    "multi_arch_images": "workflow files",
    "environments": "workflow files",
    "deploy_cloud": "workflow files",
    "publish_package": "workflow files",
}

# Instruction files that belong to one tool: off the map, but followed when they are removed.
TOOL_FILES = [
    ("cursor_rules", "Cursor rules"),
    ("copilot_instructions", "Copilot instructions"),
    ("gemini_md", "GEMINI.md"),
    ("windsurf_rules", "Windsurf rules"),
]
# What each practice is, for a reader who builds software and has never set up a coding agent.
# What it is for, not how it is detected (that is `what` in ITEMS). No figure. Set in a monospace font.
ABOUT_MAX, READING_MAX = 110, 140
ABOUT = {
    "instructions": "A file in the repo that tells coding agents how the project works: commands, conventions, pitfalls.",
    "multi_tool": "Instruction files for two or more agent tools side by side, such as CLAUDE.md next to AGENTS.md.",
    "scoped_instructions": "Extra instruction files inside subfolders, so an agent gets the rules of the package it works in.",
    "agents_md": "AGENTS.md: an instruction file format shared by many coding agents, not tied to one vendor.",
    "claude_md": "CLAUDE.md: the instruction file Claude Code loads at the start of every session.",
    "agents_dir": "A .agents/ folder at the repo root for skills and other files that several agent tools can read.",
    "ai_docs": "llms.txt: a plain-text map of a project's docs, published for language models to read.",
    "memory": "Notes an agent writes for itself in the repo, to recall context in later sessions.",
    "skills": "Folders of instructions and scripts an agent loads when a task calls for them, one job per skill.",
    "commands": "Saved prompts a developer runs by name inside the agent, such as /review or /release.",
    "subagents": "Named helper agents with their own instructions and tools, which the main agent hands tasks to.",
    "mcp": "A config that plugs outside tools into the agent, such as a database or an issue tracker, over MCP.",
    "hooks": "Scripts that run by themselves at set points of an agent session, such as after each file edit.",
    "shared_settings": "Agent settings committed for the whole team: allowed commands, permissions, hooks, model.",
    "spec_framework": "A toolkit that has the agent write a spec, then a plan and tasks, before it writes code.",
    "plans": "Written plans for a change, kept in the repo for the agent and the reviewers to follow.",
    "task_tracker": "A task list kept in the repo, where agents pick up, update and close work items.",
    "adr": "Short documents that record an architecture decision and why it was made. Older than AI agents.",
    "agent_in_ci": "A coding agent run by GitHub Actions, for example to review, fix or answer on pull requests.",
    "cloud_env": "Setup files for agents that work on a remote machine instead of a developer's laptop.",
    "parallel_setup": "Config for running several agents at once, each in its own git worktree copy of the repo.",
    "agent_commits": "Commits written with a coding agent, which marks them with its signature.",
    "agent_prs": "Pull requests opened by a coding agent itself, often from a task given in an issue or a chat.",
    "ai_review": "A bot that reviews pull requests with a language model and leaves comments before a person does.",
    "ai_review_config": "Rules committed for an AI reviewer: what to check, what to skip, the team's review standards.",
    "ai_policy": "A document that tells contributors whether and how they may use AI tools, and how to say so.",
    "cursor_rules": "Cursor's own instruction files, read by the Cursor editor and its agent.",
    "copilot_instructions": "GitHub Copilot's own instruction file, read by Copilot in the editor and on GitHub.",
    "gemini_md": "GEMINI.md: the instruction file of Google's Gemini CLI, its counterpart to CLAUDE.md.",
    "windsurf_rules": "Windsurf's own instruction files, read by the Windsurf editor and its agent.",
    # the practices read as unions of traces (TRACES)
    "issue_forms": "Issues are filed through a template or a form that asks for what the team needs.",
    "pr_template": "Pull requests open on a template the author fills in.",
    "toolchain_pinned": "The language or package manager version is pinned in the repo.",
    "compose_dev": "A Docker Compose file starts the services the project needs.",
    "task_runner": "Common tasks have one entry point: a Makefile, a justfile, a Taskfile.",
    "editor_settings": "Editor settings are shared in the repo.",
    "env_example": "An example file lists the settings a developer must provide.",
    "stale_bot": "Issues and pull requests left without activity are marked or closed by a bot.",
    "dev_env_declared": "The development environment is declared as code: a dev container, Nix, devbox.",
    "patched_deps": "Third-party packages are patched inside the repo, the patch files committed.",
    "auto_label": "Pull requests are labelled by the files they touch.",
    "ci_concurrency": "A new push cancels the CI runs it makes stale, in one workflow or more.",
    "ci_timeouts": "Some CI jobs or steps have a time limit.",
    "formatter_config": "A formatter sets the code's layout, its config committed.",
    "ci_cache": "CI keeps dependencies and build outputs between runs.",
    "ci_multi_os": "Some CI jobs run on Windows or macOS.",
    "e2e_browser": "End-to-end tests drive a real browser.",
    "coverage": "Test coverage is measured.",
    "ci_path_filters": "Some CI workflows or jobs run only when a change touches the files they cover.",
    "ci_services": "CI starts service containers beside a job, such as a database or a cache.",
    "merge_queue": "Pull requests wait in line and are tested together before they land.",
    "spellcheck": "Spelling is checked by a tool.",
    "actionlint": "The CI workflows are linted.",
    "ci_matrix": "CI repeats its jobs over a matrix of versions or systems.",
    "lint_staged": "Git hooks check only the files staged for the commit.",
    "app_token": "Some CI tasks act as a GitHub App, with a token of the app's own.",
    "release_automation": "A workflow creates the release; a person may still start it.",
    "container_images": "CI builds container images and pushes them to a registry.",
    "multi_arch_images": "Images are built for ARM as well as x86.",
    "environments": "Some CI jobs run in a GitHub environment, which can hold their secrets and require an approval.",
    "deploy_cloud": "A workflow deploys: the product, a preview, its docs or a test setup.",
    "publish_package": "CI publishes the package to its registry.",
    "changelog": "A changelog is kept at the root.",
    "docs_site": "The documentation site is built from the repo.",
    "change_convention": "Commit or pull request titles follow a convention a check enforces.",
    "changesets": "Each change carries a note of its own, gathered into the changelog at a release.",
    "preview_deploys": "Pull requests get a preview deployment, which the host's bot posts on them.",
}
# The rows the page shows: What moved holds a move of 3 pro repos or more, the main removal
# ranking what MIN_BASE pro repos or more ever had, so that no ranked row is under the floor of a
# percentage; the others are chips. Readings are written for those rows only. The page reads SHOWN_LEFT from meta.json.
SHOWN_MOVE, SHOWN_LEFT = 3, MIN_BASE
# The practices of each section of Practices (Build, Test, Secure) the page shows before a button shows the rest: the
# largest shares of the pro scene.
SHOWN_PRACTICES = 5
# What stayed, a list of its own beside What left: of the pro repos that had a practice this many snapshots ago or
# earlier, a year, the share that still have it today. A year, so that a practice is kept only
# where it had the time to go: a practice most repos added this year is in neither list, not at the top of this one.
STAYED_BACK = 12
# A list cut to its first rows (and What moved to its first and last) shows whole when the cut would hide fewer rows than this.
CUT_MIN = 3
shown_move = lambda mv: max(mv["gained"], mv["lost"]) >= SHOWN_MOVE  # as the page filters What moved
# For the repos that removed a practice: something they may have today, and how to say it.
LEFT_FOR = {
    "claude_md": ("agents_md", "have an AGENTS.md today"),
    "cursor_rules": ("agents_md", "have an AGENTS.md today"),
    "copilot_instructions": ("agents_md", "have an AGENTS.md today"),
    "multi_tool": ("agents_md", "kept an AGENTS.md"),
    "commands": ("skills", "ship skills today"),
    "subagents": ("skills", "ship skills today"),
    "mcp": ("skills", "ship skills today"),
    "agent_in_ci": ("ai_review", "still have an AI reviewer on pull requests"),
    "agent_commits": ("agent_prs", "still have agent-opened pull requests"),
}

# Context slices. A monorepo has a workspace file or a packages directory at the root.
WORKSPACE = {
    "pnpm-workspace.yaml",
    "turbo.json",
    "nx.json",
    "lerna.json",
    "rush.json",
    "go.work",
    "packages",
    "apps",
    "crates",
}
LANGUAGES = {
    "TypeScript": "TypeScript or JS",
    "JavaScript": "TypeScript or JS",
    "Python": "Python",
    "Go": "Go or Rust",
    "Rust": "Go or Rust",
}
CONTEXT_ITEMS = (
    "instructions",
    "scoped_instructions",
    "skills",
    "commands",
    "hooks",
    "mcp",
    "agent_in_ci",
    "agent_commits",
    "agent_prs",
    "ai_review",
)
# cut by the same slices for a report note alone (Repo size): not a row of By context's table
CONTEXT_NOTES = ("e2e_browser",)
# a slice under MIN_BASE repos is hidden: its shares would be percentages on too small a base

# What a skill is for, read from its name. The first pattern that matches wins.
SKILL_JOBS = [
    (job, re.compile(pattern))
    for job, pattern in [
        ("Code review", r"review|deslop|slop|code-quality|simplif"),
        (
            "Pull requests and git",
            r"(?:^|-)prs?(?:-|$)|pull-request|commit|branch|merg|stack|worktree|(?:^|-)git(?:-|$)|squash|backport|shepherd",
        ),
        (
            "Tests and QA",
            r"test|e2e|playwright|vitest|(?:^|-)qa(?:-|$)|smoke|flak|tdd|snapshot|fuzz|verif|(?:^|-)evals?(?:-|$)|bench|dogfood|acceptance",
        ),
        (
            "Releases and upkeep",
            r"releas|changelog|version|bump|upgrade|dependenc|(?:^|-)dep(?:-|$)|publish|dependabot|deploy|deprecat|breaking|vendor|update-(?!docs)",
        ),
        (
            "Debugging and triage",
            r"debug|triag|investigat|reproduce|(?:^|-)fix|incident|profil|diagnos|monitor|(?:^|-)logs?(?:-|$)|doctor|root-cause|(?:^|-)bugs?(?:-|$)",
        ),
        ("Migrations and data", r"migrat|clickhouse|sql|(?:^|-)db(?:-|$)|quer|drizzle|warehouse|schema|postgres"),
        (
            "Docs and writing",
            r"doc|guide|tutorial|blog|copy|comment|mintlify|prose|handbook|announc|translat|i18n|locale",
        ),
        (
            "Planning, specs and issues",
            r"spec|plan|issue|ticket|linear|backlog|grill|prototype|(?:^|-)adr(?:-|$)|retro|architecture|domain-model|codebase-design",
        ),
        (
            "Design and UX",
            r"design|(?:^|-)ui\d?(?:-|$)|(?:^|-)ux(?:-|$)|figma|animat|a11y|accessib|illustrat|icon|gesture|visual|taste|storybook|stories|styling",
        ),
        ("Frontend code", r"frontend|react|tailwind|css|component|svelte"),
        ("Agent setup", r"skill|agents-md|mcp|agent|codex|cursor|llm|(?:^|-)ai(?:-|$)"),
    ]
]
OTHER_JOB = "Codebase how-tos"

# The four levels of evidence a claim can carry: id, the question it answers, what it takes.
LEVELS = [
    (
        "observed",
        "Do teams do it?",
        "Counted in public repos, by us or in a published study: what teams do and keep, not whether it works.",
    ),
    ("reported", "What do practitioners say?", "Interviews, write-ups and vendor claims, taken as told."),
    ("tested", "Does it work when we run it?", "Run by us on a real task, in a way anyone can repeat."),
    (
        "benchmarked",
        "Does it beat the alternative?",
        "Compared with and without the practice under controlled conditions, by us or in a study.",
    ),
]
# Published studies quoted in Build's outside evidence. Figures are from their abstracts.
STUDIES = {
    "context_bench": ("Evaluating AGENTS.md, arXiv 2602.11988", "https://arxiv.org/abs/2602.11988"),
    "agent_readmes": ("Agent READMEs, arXiv 2511.12884", "https://arxiv.org/abs/2511.12884"),
    "harness": (
        "Harness Engineering for Agentic AI Coding Tools, arXiv 2602.14690",
        "https://arxiv.org/abs/2602.14690",
    ),
    "skillsbench": ("SkillsBench, arXiv 2602.12670", "https://arxiv.org/abs/2602.12670"),
    "review_agents": ("Code Review Agents in Pull Requests, arXiv 2604.03196", "https://arxiv.org/abs/2604.03196"),
    "review_practice": ("Automated Code Review In Practice, arXiv 2412.18531", "https://arxiv.org/abs/2412.18531"),
    "test_coverage": (
        "Test Coverage Analysis of Agentic Pull Requests, arXiv 2607.18057",
        "https://arxiv.org/abs/2607.18057",
    ),
    "weak_oracles": ("All Smoke, No Alarm, arXiv 2606.18168", "https://arxiv.org/abs/2606.18168"),
    "do_not_deny": ('When "Do Not" Is Not Deny, arXiv 2608.23550', "https://arxiv.org/abs/2608.23550"),
    "dep_decisions": (
        "Towards a Benchmark for Dependency Decision-Making, arXiv 2601.00205",
        "https://arxiv.org/abs/2601.00205",
    ),
}
# Review rule files worth opening, and the reviewer each one belongs to.
REVIEW_FILES = {
    ".coderabbit.yaml": "CodeRabbit rules",
    ".coderabbit.yml": "CodeRabbit rules",
    "BUGBOT.md": "Cursor Bugbot rules",
    "cubic.yaml": "cubic rules",
    "REVIEW.md": "review instructions",
    "config.json": "Greptile rules",
}

# Setups (`builds` in the data): the first rule a repo satisfies names its setup. Decided after reading the pro
# scene repo by repo (analyze.py --matrix).
EXTENSIONS = ("skills", "commands", "subagents", "mcp", "hooks", "shared_settings")
AUTOMATION = ("agent_in_ci", "cloud_env", "parallel_setup")
# Agents at work in a repo (a report note): they sign commits, review pull requests or open them, in that order
AT_WORK = ("agent_commits", "ai_review", "agent_prs")
# The practices that guard what CI may do and what it runs: its token's rights, the actions it runs, the secrets its jobs reach,
# what it builds. The report note on What moved counts those among its TOP_MOVES first rows.
CI_GUARDS = ("token_scoped", "checkout_no_token", "app_token", "pinned", "zizmor", "signed_builds", "environments")
TOP_MOVES = 10
BUILDS = [
    (
        "full",
        "Full rig",
        "Instructions, two or more kinds of extension, and automation: the agent runs in CI, in the cloud or in parallel worktrees.",
        lambda f: f["instructions"] and sum(f[k] for k in EXTENSIONS) >= 2 and any(f[k] for k in AUTOMATION),
    ),
    (
        "workshop",
        "Workshop",
        "Instructions plus tooling for the agent (skills, commands, hooks), short of a full rig.",
        lambda f: f["instructions"] and any(f[k] for k in EXTENSIONS),
    ),
    (
        "briefed",
        "Briefed",
        "An instruction file and no tooling: the agent is told how the repo works and left to it.",
        lambda f: f["instructions"],
    ),
    (
        "unmarked",
        "No setup, agent at work",
        "No instruction file, yet agents sign commits or open pull requests: the setup lives on developers' machines.",
        lambda f: f["agent_commits"] or f["agent_prs"],
    ),
    # the thresholds of the two practices: a repo with one or two signed commits, or one agent pull request, is here
    (
        "none",
        "No visible agent",
        "No instruction file, under %d agent-signed commits in %d days and under %d agent-opened pull requests."
        % (MIN_SIGNED_COMMITS, COMMIT_DAYS, MIN_AGENT_PRS),
        lambda f: True,
    ),
]


def wilson(k, n, z=1.96):
    if not n:
        return 0.0, 0.0
    p = k / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - half) / (1 + z * z / n)), min(1.0, (centre + half) / (1 + z * z / n))


def share(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "p": round(k / n, 4) if n else 0, "lo": round(lo, 4), "hi": round(hi, 4)}


def lead(pro, ladder):
    """How many times the pro share is the ladder's, worked out from the four counts: "4.3×", or None when fewer than MIN_LEAD
    repos of either league have the practice.

    Rounded half up on the exact ratio, to one decimal under LEAD_WHOLE and to a whole number from it, so that 9.96
    reads "10×". Not from shares already rounded to four decimals: those give 74× for 31 of 98 against 1 of 230, where
    the ratio is 72.8.
    """
    if pro["k"] < MIN_LEAD or ladder["k"] < MIN_LEAD:
        return None
    ratio = Fraction(pro["k"] * ladder["n"], pro["n"] * ladder["k"])
    tenths = math.floor(ratio * 10 + Fraction(1, 2))
    return "%d.%d×" % divmod(tenths, 10) if tenths < 10 * LEAD_WHOLE else "%d×" % math.floor(ratio + Fraction(1, 2))


def percent(p):
    """A share as the page prints it, the one way a sentence writes a percentage: whole percent, rounded half up as the page's
    Math.round does on the same p * 100 (Python's round() takes a half to the even number: 12.5 would read 12), and "<1%" for a
    share above zero and under half a percent. Every percentage of a sentence goes through here."""
    return "<1%" if 0 < p < 0.005 else "%d%%" % points(p)


def pc(x):
    """A share as a sentence prints it, in whole percent. A share whose base is under MIN_BASE is never a percentage: a
    sentence says its count instead, so this refuses one (a share given without its base, a point of a series, is the league's)."""
    if x.get("n", MIN_BASE) < MIN_BASE:
        raise ValueError("a percentage on a base of %d repos, under %d: say the count" % (x["n"], MIN_BASE))
    return percent(x["p"])


# A small count in letters, as the page's sentences write it ("three months", not "3 months").
NUMBER_WORDS = (
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
)


def words(n):
    return NUMBER_WORDS[n] if 0 <= n < len(NUMBER_WORDS) else str(n)


def months(n):
    """ "three months", "one month"."""
    return "%s month%s" % (words(n), "" if n == 1 else "s")


def span_copy(back, shown):
    """What the page says of the months between "then" and now (back: BACK) and of the least move that is shown (shown:
    SHOWN_MOVE), written here so that the page's source types neither: the heading's intro, the note under What moved,
    the intro of Every number, and the short phrases that name the span ("In three months", the map's key, the tails'
    label and the column of Every number, in digits). In letters where the page says "three", in digits where it labels
    a chart or a column."""
    digits = "%d month%s" % (back, "" if back == 1 else "s")
    return {
        "back_in": "In %s" % months(back),
        "back_key": "where it was %s ago" % months(back),
        "back_ago": "%s ago" % digits,
        "back_col": digits,
        "moves_intro": "%s-month change in pro adoption, in percentage points. The repos are today's at both dates, so each change "
        "is a repo adding or removing it; a repo created since the earlier date that has it today counts as adding it. The rows "
        "go from the largest rise to the largest fall." % (words(back).capitalize()),
        "moves_floor": "Moves of fewer than %s repo%s are left out." % (words(shown), "" if shown == 1 else "s"),
        "all_intro": 'Share of repos with the trace today, 95%% interval in brackets. "Kept": of the pro repos that had it %s or more '
        "months ago, the share that still does; left out where a file moved or rewritten reads as a removal, as in "
        "What left." % words(back),
    }


def count(rule, hit):
    """Hits of one rule in one tree, re-checked against the rules as they are now.

    A scan keeps the first paths of every rule. When it kept all of them, they are matched
    again, so tightening a rule does not need a new scan. Past that, the scan is trusted.
    """
    if not hit or not hit["n"]:
        return 0
    if hit["n"] > len(hit["sample"]):
        return hit["n"]
    return sum(1 for path in hit["sample"] if fp.still_valid(rule, path))


def features(scan, i):
    """Answers for one repo at snapshot i, or None when the repo has no known state then."""
    s = scan["snaps"][i]
    if s is None:
        return None
    st = scan["sets"][s["set"]]
    hits, root = st["hits"], set(st["root"])
    n = lambda rule: count(rule, hits.get(rule))
    families = [r for r in fp.INSTRUCTION_RULES if n(r)]
    by = s["commits90"]["by"]
    f = {
        "instructions": bool(families),
        "multi_tool": len(families) >= 2,
        "scoped_instructions": any(n(r) > hits[r]["root"] for r in ("claude_md", "agents_md") if n(r)),
        "agents_md": n("agents_md") > 0,
        "claude_md": n("claude_md") > 0,
        "agents_dir": ".agents" in root,
        "ai_docs": n("ai_docs") > 0,
        "memory": n("memory") > 0,
        "skills": n("skills") > 0,
        "commands": n("commands") > 0,
        "subagents": n("subagents") > 0,
        "mcp": n("mcp_config") > 0,
        "hooks": n("hooks_files") > 0 or bool(s["settings"] and s["settings"]["hooks"]),
        "shared_settings": n("shared_settings") > 0,
        "spec_framework": n("spec_framework") > 0,
        "plans": n("plans") > 0,
        "task_tracker": n("task_tracker") > 0,
        "adr": n("adr") > 0,
        "agent_in_ci": bool(s["ci"]),
        "cloud_env": n("cloud_agent_env") > 0,
        "parallel_setup": n("parallel_setup") > 0,
        "agent_commits": s["commits90"]["signed"] >= MIN_SIGNED_COMMITS,
        "ai_review_config": n("ai_review_config") > 0,
        "ai_policy": n("ai_policy") > 0,
    }
    f.update(traced(s, n))
    for tool, _, roots, rules in TOOLS:
        f["cfg_" + tool] = bool(roots & root) or any(n(r) for r in rules)
        f["act_" + tool] = by.get(tool, 0) >= 1 or tool in s["ci"]
    return f


def traced(s, n):
    """The practices of TRACES at one snapshot: each is there when any of its traces is (all the parts of one joined by "+"). `n` counts a path rule's hits in the
    snapshot's tree. A snapshot with no `ops` (read before the scan read them), or no `sec`, has none of their traces."""
    ops, sec = s.get("ops") or {}, s.get("sec") or {}
    read = {
        "rule": lambda name: n(name) > 0,
        "ci": lambda name: name in (ops.get("ci") or ()),
        "pkg": lambda name: name in (ops.get("pkg") or ()),
        "sec": lambda name: bool(sec.get(name)),
    }
    one = lambda part: read[part.split(":", 1)[0]](part.split(":", 1)[1])
    return {key: any(all(map(one, trace.split("+"))) for trace in traces) for key, traces in TRACES.items()}


def preview_bots(api):
    """The hosts whose preview bot left MIN_BOT_COMMENTS or more of a repo's latest review and pull request comments."""
    found = collections.Counter()
    for source in ("review_bots", "pr_comment_bots"):
        for login, n in api[source].items():
            host = PREVIEW_BOTS.get(login.lower())
            if host:
                found[host] += n
    return sorted(host for host, n in found.items() if n >= MIN_BOT_COMMENTS)


def api_features(api):
    if api is None:
        return None
    reviewers = collections.Counter()
    for source in ("review_bots", "pr_comment_bots"):
        for login, count in api[source].items():
            known = login.startswith(AI_REVIEWERS)
            by_name = source == "review_bots" and AI_REVIEWER_NAME.search(login) and not login.startswith(NOT_REVIEWERS)
            if known or by_name:
                reviewers[login.replace("[bot]", "")] += count
    agent_prs = sum(api["agent_prs"].values())
    return {
        "agent_prs": agent_prs >= MIN_AGENT_PRS,
        "ai_review": sum(reviewers.values()) >= MIN_REVIEW_COMMENTS,
        "reviewers": dict(reviewers),
        "pr_agents": api["agent_prs"],
        "agent_pr_share": agent_prs / api["prs"] if api["prs"] else 0,
        "preview_deploys": bool(preview_bots(api)),
        "preview_hosts": preview_bots(api),
        "security_bots": security_bots(api),
        "settings": security_settings(api),
        # the API's security block as read (rule types, protected, counts: no person), for the readings of Secure
        "security": api.get("security") or {},
    }


# The practices read from the GitHub API, today only: a repo's answer today is the API's, and it has none at a snapshot
API_PRACTICES = ("agent_prs", "ai_review", "preview_deploys")


def load(league):
    repos = []
    for r in read_json(DATA / ("panel_%s.json" % league)):
        scan_path = DATA / "scan" / (slug(r["name"]) + ".json")
        api_path = DATA / "api" / (slug(r["name"]) + ".json")
        if not scan_path.exists() or not api_path.exists():
            continue
        scan, api = read_json(scan_path), read_json(api_path)
        # `api_on`: the day the API was read for this repo, which its file carries (`as_of`); the run date for a repo read with the run
        r = dict(r, scan=scan, api=api_features(api), api_on=api["as_of"])
        r["f"] = [features(scan, i) for i in range(len(scan["snaps"]))]
        r["g"] = [lens_features(scan, i) for i in range(len(scan["snaps"]))]
        r["now"] = dict(r["f"][-1], **{key: r["api"][key] for key in API_PRACTICES})  # pyright: ignore[reportCallIssue, reportArgumentType]  (a scan's last snapshot is never None)
        repos.append(r)
    return repos


def has(f, key):
    """One answer at one snapshot. A repo with no state there did not exist yet: it does not have it."""
    return bool(f and f[key])


def series(repos, key):
    """Adoption of one feature at every snapshot, over the whole panel.

    The panel is fixed: it is today's repos at every date, and a repo created since a snapshot counts there as not
    having the feature. Every point has today's base, so the last one is today's figure and a change is repos.
    """
    return [share(sum(1 for r in repos if has(r["f"][i], key)), len(repos)) for i in range(len(repos[0]["f"]))]


def retention(repos, key):
    """Of the repos that had the feature at least BACK months ago, how many still do."""
    had = [r for r in repos if any(f and f[key] for f in r["f"][:-BACK])]
    return share(sum(1 for r in had if r["f"][-1][key]), len(had))


def new_since(repos, i):
    """The repos of the panel with no state at snapshot i: those created since."""
    return sum(1 for r in repos if r["f"][i] is None)


def moves(repos, key):
    """Repos that gained or lost the feature since BACK snapshots ago, over the whole panel, as series() counts it.

    A repo created since that has the feature today gained it. It is counted among the gains and again in "new", so
    that today's count is then's count plus the gains less the losses, and a new repo can be told from a change of habit.
    """
    pairs = [(r["f"][-1 - BACK], r["f"][-1]) for r in repos]
    return {
        "gained": sum(1 for a, b in pairs if b[key] and not has(a, key)),
        "lost": sum(1 for a, b in pairs if has(a, key) and not b[key]),
        "new": sum(1 for a, b in pairs if a is None and b[key]),
    }


def removed_by(repos, key, i):
    """Of the repos that removed a feature over the last BACK snapshots (moves()' "lost": they had it BACK snapshots ago
    and not today), those that no longer had it at snapshot i: the timing of those removals, over the same repos. A
    sentence that gives the "lost" count dates it from here, not from `when` of What left: that one counts every repo
    that ever had the practice and not today, by the snapshot it was gone by, so it holds repos that added it after the
    earlier date."""
    return sum(1 for r in repos if has(r["f"][-1 - BACK], key) and not r["f"][-1][key] and not has(r["f"][i], key))


def points(p):
    """A share in whole percent as the page prints it: rounded half up, as the page's Math.round does on the same p * 100."""
    return math.floor(p * 100 + 0.5)


def change(shares):
    """The change in points over the last BACK snapshots of a series of shares: the difference of the two shares as the page
    prints them, so that a change and the shares beside it subtract: "79% to 67%" reads −12, where the unrounded shares
    could give −11."""
    return points(shares[-1]) - points(shares[-1 - BACK])


def moved(items):
    """The rows of What moved, in their order: the practices with a history that SHOWN_MOVE pro repos or more added or removed,
    the largest rise in points first, as printed; a tie by the larger change in repos (added less removed), then by the more
    repos that added it, then in the order of the data."""
    rows = [i for i in items if i["history"] and i.get("in_moves", True) and shown_move(i["pro"]["moves"])]
    net = lambda mv: mv["gained"] - mv["lost"]
    return [
        i["id"]
        for i in sorted(
            rows, key=lambda i: (-i["pro"]["change"], -net(i["pro"]["moves"]), -i["pro"]["moves"]["gained"])
        )
    ]


def rule_series(r, rule):
    """Whether one fingerprint rule matches at every snapshot, None before the repo's history."""
    sets = r["scan"]["sets"]
    return [None if s is None else count(rule, sets[s["set"]]["hits"].get(rule)) > 0 for s in r["scan"]["snaps"]]


def departures(repos, series_of):
    """Repos that had something at any snapshot, those of them that do not today, and the snapshot it was gone by.

    A repo that first shows it today is in the count: what is left once the leavers are taken out is today's count.
    """
    ever, gone, when = 0, [], [0] * len(repos[0]["f"])
    for r in repos:
        s = series_of(r)
        if not any(s):
            continue
        ever += 1
        if not s[-1]:
            gone.append(r)
            when[max(i for i, x in enumerate(s) if x) + 1] += 1
    return ever, gone, when


def stayed(repos, series_of):
    """Of the repos that had something STAYED_BACK snapshots ago or earlier, those that still have it today: What stayed."""
    had = [s for s in map(series_of, repos) if any(s[:-STAYED_BACK])]
    return share(sum(1 for s in had if s[-1]), len(had))


def in_left(row):
    """A row of What left: SHOWN_LEFT pro repos or more ever had it, and SHOWN_MOVE or more took it out (as What moved leaves out
    the moves of fewer repos: two removals out of 160 are not what left)."""
    return row["left"]["n"] >= SHOWN_LEFT and row["left"]["k"] >= SHOWN_MOVE


def in_stayed(row):
    """A row of What stayed: SHOWN_LEFT pro repos or more had it a year ago or earlier (STAYED_BACK), and most of them still do."""
    return row["stayed"]["n"] >= SHOWN_LEFT and 2 * row["stayed"]["k"] > row["stayed"]["n"]


def left_lists(rows):
    """The two lists of the Report tab, as ids in their order (each shows its first SHOWN_PRACTICES rows, then a
    button): What left, the largest share taken out first, then more repos, then a smaller base; What stayed, the
    largest share kept first, then a larger base. A practice is in both where 3 pro repos or more took it out and most
    of those that had it a year ago kept it."""
    return {
        "left": [
            row["id"]
            for row in sorted(
                filter(in_left, rows), key=lambda row: (-row["left"]["p"], -row["left"]["k"], row["left"]["n"])
            )
        ],
        "stayed": [
            row["id"]
            for row in sorted(filter(in_stayed, rows), key=lambda row: (-row["stayed"]["p"], -row["stayed"]["n"]))
        ],
    }


def left_copy(dates):
    """The intros of What left and What stayed: they hold the first snapshot, the floors and the span of What stayed."""
    first = AS_OF.replace(year=int(dates[0][:4]), month=int(dates[0][5:7]), day=1).strftime("%B %Y")
    span = "a year" if STAYED_BACK == 12 else months(STAYED_BACK)
    return {
        "left_intro": "Of the pro repos that had a practice at any monthly snapshot since %s, the share that took it out, and "
        "when. Keeping a file costs nothing, so a removal says more than a stay. Most taken out first. Practices fewer than %s "
        "pro repos took out are left out." % (first, words(SHOWN_MOVE)),
        "stayed_intro": "Of the pro repos that had a practice %s ago or earlier, the share that still have it: each had %s to "
        "take it out. Most kept first. Only what %d pro repos or more had then, and most of them kept; a practice most repos added "
        "since is too new to tell." % (span, span, SHOWN_LEFT),
        # the head of its list's figures
        "stayed_cap": "Pro repos that had it %s ago and still do" % span,
    }


def left(view, items, tools=()):
    """What the pro repos took out: for each practice of `items` that What left can rank (a monthly history, not read from a file's
    text, not llms.txt) and each instruction file of one tool in `tools`, those that had it at a snapshot and no longer do. `view` is
    the pro scene as the practices were counted over it: the league for ITEMS, the lens view for LENS_ITEMS. Every candidate has its
    row, on the page or not: main() keeps those of the practices on the page."""
    sources = [
        (i, lambda r, key=i["id"]: [f and f[key] for f in r["f"]])
        for i in items
        if i["in_moves"] and i["id"] not in NO_KEEP_RATE
    ]
    sources += [
        (
            {"id": rule, "label": label, "field": "build", "kind": "agent", "about": ABOUT[rule]},
            lambda r, rule=rule: rule_series(r, rule),
        )
        for rule, label in tools
    ]
    rows = []
    for item, series_of in sources:
        ever, gone, when = departures(view, series_of)
        if not ever:
            continue
        key = item["id"]
        row = {
            "id": key,
            "label": item["label"],
            "field": item["field"],
            **({"lens": item["field"]} if item["field"] != "build" else {}),
            "kind": item["kind"],
            "about": item["about"],
            "left": share(len(gone), ever),
            "stayed": stayed(view, series_of),
            "when": when,
        }
        # what the leavers have today, from 3 of them: with none it would read "all 0"
        if len(gone) >= 3 and (key in LEFT_FOR or key in LENS_LEFT_FOR):
            test, words = (
                LENS_LEFT_FOR[key]
                if key in LENS_LEFT_FOR
                else ((lambda f, feature=LEFT_FOR[key][0]: f[feature]), LEFT_FOR[key][1])
            )
            now = sum(1 for r in gone if test(r["now"]))
            row["after"] = "%s %s" % ("all %d" % now if now == len(gone) else "%d of the %d" % (now, len(gone)), words)
        rows.append(row)
    return rows


def tip_tree(r):
    return r["scan"]["sets"][r["scan"]["snaps"][-1]["set"]]


def own_files(r):
    """A repo's size: its number of files at the last snapshot, as that snapshot stored it (`files`). A scan older than
    `files` has none: its size is `tip_tree(r)["n_files"]`, the count of the first snapshot that shares the tip's set of
    matched paths, which is the tip's own count when the scan has a single snapshot."""
    return r["scan"]["snaps"][-1].get("files", tip_tree(r)["n_files"])


def short_count(n):
    """A threshold for a label: two significant digits, in thousands from 1,000 with one decimal at most and none when it is 0
    (2,350 is "2.4k", 12,345 is "12k", 640 stays "640")."""
    n = int(round(n, 2 - len(str(int(n)))))
    if n < 1000:
        return str(n)
    k = "%.1f" % (n / 1000)
    return (k[:-2] if k.endswith(".0") else k) + "k"


def contexts(repos, keys=CONTEXT_ITEMS):
    """Adoption today inside slices of one league: by repo size, layout, main language and age, for the practices of `keys` (those
    of CONTEXT_ITEMS on the page)."""
    files = own_files
    sizes = sorted(files(r) for r in repos)
    small, large = sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]
    mono = lambda r: bool(WORKSPACE & set(tip_tree(r)["root"]))
    groups = [
        # "< 2.4k files", "> 6.7k files": the threshold is rounded, so ">" is as exact as "or more" would be
        (
            "Size",
            [
                ("Small", "< %s files" % short_count(small), lambda r: files(r) < small),
                ("Mid", "", lambda r: small <= files(r) < large),
                ("Large", "> %s files" % short_count(large), lambda r: files(r) >= large),
            ],
        ),
        ("Layout", [("Single package", "", lambda r: not mono(r)), ("Monorepo", "", mono)]),
        (
            "Main language",
            [
                (name, "", lambda r, name=name: LANGUAGES.get(r["language"], "Other") == name)
                for name in ("TypeScript or JS", "Python", "Go or Rust", "Other")
            ],
        ),
        (
            "Created",
            [
                ("Before 2023", "", lambda r: r["created_at"] < "2023"),
                ("2023 or later", "", lambda r: r["created_at"] >= "2023"),
            ],
        ),
    ]
    out = {"groups": [], "rows": [{"id": k, "label": LABEL[k], "cells": []} for k in keys]}
    for name, slices in groups:
        shown = []
        for label, sub, test in slices:
            members = [r for r in repos if test(r)]
            if len(members) < MIN_BASE:
                continue
            shown.append({"label": label, "sub": sub, "n": len(members)})
            for row in out["rows"]:
                row["cells"].append(share(sum(1 for r in members if r["now"][row["id"]]), len(members)))
        out["groups"].append({"name": name, "slices": shown})
    # the rows from the practice the most repos of the league have to the one the fewest have: a table's order says
    # something
    out["rows"].sort(key=lambda row: (-sum(1 for r in repos if r["now"][row["id"]]), row["label"]))
    return out


def in_slice(ctx, key, label):
    """Share of one practice inside one named slice of a league."""
    labels = [s["label"] for g in ctx["groups"] for s in g["slices"]]
    return next(row for row in ctx["rows"] if row["id"] == key)["cells"][labels.index(label)]


MODEL_NAME = re.compile(r"(?:Opus|Sonnet|Haiku|Fable) \d+(?:\.\d+)?")
MODEL_REPOS = 5


def model_history(leagues):
    """Share of each month's Claude-signed commits by the model named in the trailer.

    The commits that name a model and those that only say Claude are counted over the same months, those of the grid: a
    scan holds the months of its whole history, which starts before the first snapshot, and a count over those would
    cover a month the other does not."""
    counts, unnamed, seen_in = collections.defaultdict(collections.Counter), 0, collections.defaultdict(set)
    months = sorted({d.isoformat()[:7] for d in snapshot_dates()})
    for repos in leagues.values():
        for r in repos:
            for key, n in r["scan"]["models"].items():
                month, _, name = key.partition(" ")
                if month not in months:
                    continue
                name = re.sub(r"\(.*?\)", "", name).replace("claude", "").strip()
                if name:
                    counts[name.title()][month] += n
                    seen_in[name.title()].add(r["name"])
                else:
                    unnamed += n
    totals = [sum(c[m] for c in counts.values()) for m in months]
    rows = []
    for name, c in counts.items():
        shares = [round(c[m] / t, 4) if t else 0 for m, t in zip(months, totals)]
        # a row is a model's name as Claude Code writes it, in MODEL_REPOS repos or more: a display name is typed by
        # whoever commits, so one repo could otherwise put a made-up model on the page. Its commits stay in the month's
        # total either way
        if (
            max(shares) >= 0.05
            and sum(c.values()) >= 20
            and MODEL_NAME.fullmatch(name)
            and len(seen_in[name]) >= MODEL_REPOS
        ):
            first = next(i for i, s in enumerate(shares) if s >= 0.01)
            rows.append({"name": name, "first": first, "shares": shares, "commits": sum(c.values())})
    rows.sort(key=lambda r: (r["first"], r["name"]))
    return {"months": months, "totals": totals, "rows": rows, "unnamed": unnamed, "named": sum(totals)}


def build_of(f):
    return next(b for b in BUILDS if b[3](f))[0]


def builds(leagues, keys):
    """The Setups, and the usual kit of each: the practices of `keys` (main(): the agent practices of ITEMS on the page, off the
    map's double count of CLAUDE.md and AGENTS.md) that a quarter or more of its pro repos have."""
    out = []
    for key, name, tagline, _ in BUILDS:
        members = {lg: [r for r in repos if build_of(r["now"]) == key] for lg, repos in leagues.items()}
        pro = members["pro"]
        # with its count and its base, the build's pro repos: the page gives a share of a small build as a count (MIN_BASE)
        kit = [
            {
                "label": LABEL[k],
                "share": round(sum(r["now"][k] for r in pro) / len(pro), 3),
                "k": sum(1 for r in pro if r["now"][k]),
                "n": len(pro),
            }
            for k in keys
            if pro and sum(r["now"][k] for r in pro) / len(pro) >= 0.25
        ]
        kit.sort(key=lambda k: -k["share"])
        out.append(
            {
                "id": key,
                "name": name,
                "tagline": tagline,
                "kit": kit[:12],
                "pro": share(len(pro), len(leagues["pro"])),
                "ladder": share(len(members["ladder"]), len(leagues["ladder"])),
                "examples": [r["name"] for r in sorted(pro, key=lambda r: -r["stars"])[:8]],
            }
        )
    return out


# The ranked lists of Tool traces hold the KIT_ROWS labels in the most pro repos. The Skills card names every skill name found in
# TRAVEL_MIN pro repos or more (travelling_skills), with no cut.
KIT_ROWS, TRAVEL_MIN = 7, 3
AGENT_NAMES = {
    "claude": "Claude Code",
    "codex": "Codex",
    "cursor": "Cursor",
    "copilot": "GitHub Copilot",
    "devin": "Devin",
    "gemini": "Gemini CLI",
    "opencode": "opencode",
    "amp": "Amp",
    "jules": "Jules",
    "aider": "Aider",
    "openhands": "OpenHands",
    "droid": "Droid",
    "windsurf": "Windsurf",
    "cline": "Cline, Roo, Kilo",
    "kiro": "Kiro",
    "seer": "Sentry Seer",
    "junie": "Junie",
    "warp": "Warp",
}
REVIEWER_NAMES = {
    "chatgpt-codex-connector": "Codex",
    "copilot": "GitHub Copilot",
    "coderabbitai": "CodeRabbit",
    "cursor": "Cursor Bugbot",
    "greptile-apps": "Greptile",
    "cubic-dev-ai": "cubic",
    "devin-ai-integration": "Devin",
    "claude": "Claude",
    "vercel": "Vercel Agent",
    "graphite-app": "Graphite",
    "gemini-code-assist": "Gemini Code Assist",
}


def link_target(link):
    """Where a stored link points, from the repo's root: None when its target is null (a scan stores one only inside the
    repo), absolute or climbs out of the repo, which an older scan may hold. Never followed out of the repo."""
    to = link.get("to")
    if not to or to.startswith(("/", "~")) or "\\" in to or re.match(r"[A-Za-z]:", to):
        return None
    target = os.path.normpath(os.path.join(os.path.dirname(link["path"]), to))
    return None if target == ".." or target.startswith(("../", "/")) else target


def skill_names(scan):
    """Names of the skills a repo keeps for its agents, following linked directories."""
    names = set()
    for rule, path in scan["head_paths"]:
        if rule == "skills" and re.search(r"/skills?/", path):
            names.add(re.split(r"/skills?/", path)[-1].split("/")[0])
    for link in scan.get("links", []):
        target = link_target(link)
        if target and re.search(r"/skills?$", link["path"]):
            names.update(
                path[len(target) + 1 :].split("/")[0]
                for rule, path in scan["head_paths"]
                if rule == "skill_files" and path.startswith(target + "/")
            )
    return names


def sync_style(scan):
    """How a repo with both CLAUDE.md and AGENTS.md at the root keeps them in step."""
    # File names are matched whatever their case: some repos commit a lowercase claude.md.
    root = {i["path"].lower(): i for i in scan["instructions"] if "/" not in i["path"]}
    claude, agents = root.get("claude.md"), root.get("agents.md")
    if not (claude and agents):
        return []
    if "symlink_to" in claude or "symlink_to" in agents:
        return ["One is a symlink to the other"]
    if claude.get("pointer_only") or agents.get("pointer_only"):
        return ["One just points at the other"]
    return ["Two separate files"]


def kit(leagues):
    """Ranked lists of the tools whose traces a repo carries, drawn in Tool traces under Data. Each picker returns labels for
    one repo."""
    tip = lambda r: r["scan"]["snaps"][-1]
    lists = [
        (
            "AI reviewers on pull requests",
            "Bots with 2 or more comments on recent pull requests. All leave the same trace, so this list compares like with like.",
            lambda r: [REVIEWER_NAMES.get(k, k) for k, n in r["api"]["reviewers"].items() if n >= 2],
        ),
        # One trace lists a tool, where the practice asks for its threshold: each note says both, since a tool can then be
        # in more repos than the practice (the page says so once, over the lists).
        (
            "Agents opening pull requests",
            "One or more of the latest %d pull requests; the practice asks for %d. "
            "Found by bot account or by the agent's default branch name. A renamed branch goes unseen."
            % (LATEST_ITEMS, MIN_AGENT_PRS),
            lambda r: [AGENT_NAMES.get(k, k) for k in r["api"]["pr_agents"]],
        ),
        (
            "Agents signing commits",
            "One signed commit or more in %d days; the practice asks for %d. "
            "Claude Code signs by default; others do not, or started late." % (COMMIT_DAYS, MIN_SIGNED_COMMITS),
            lambda r: [AGENT_NAMES.get(k, k) for k in tip(r)["commits90"]["by"]],
        ),
        (
            "Agents called from CI",
            "Named in a GitHub Actions workflow.",
            lambda r: [AGENT_NAMES.get(k, k) for k in tip(r)["ci"]],
        ),
        (
            "Tool directories in the repo",
            "A directory or file that belongs to one tool. Copilot and Codex need none.",
            lambda r: [label for tool, label, _, _ in TOOLS if r["now"]["cfg_" + tool]],
        ),
    ]
    out = []
    for title, note, pick in lists:
        # each repo's labels once, in a fixed order: a set's order moves with the hash seed, and ties of most_common follow it
        tally = {
            lg: collections.Counter(x for r in repos for x in sorted(set(pick(r))) if x)
            for lg, repos in leagues.items()
        }
        rows = [
            {
                "label": label,
                "pro": share(n, len(leagues["pro"])),
                "ladder": share(tally["ladder"][label], len(leagues["ladder"])),
            }
            for label, n in tally["pro"].most_common(KIT_ROWS)
        ]
        # most pro repos first, then most ladder repos, then by name, so that ties do not follow the order the repos
        # were read
        rows.sort(key=lambda row: (-row["pro"]["k"], -row["ladder"]["k"], row["label"].lower()))
        out.append({"title": title, "note": note, "rows": rows})
    return out


def travelling_skills(pro):
    """The skill names found in TRAVEL_MIN pro repos or more, the most common first: the Skills card names them all."""
    # each repo's names once, in a fixed order: a set's order moves with the hash seed, and ties of most_common follow it
    tally = collections.Counter(x for r in pro for x in sorted(skill_names(r["scan"])) if x)
    return [name for name, n in tally.most_common() if n >= TRAVEL_MIN]


def skill_jobs(repos):
    """Skills sorted into jobs by their name, counted over the repos that ship named skills."""
    owners, skills, per_repo = collections.defaultdict(set), collections.Counter(), []
    for r in repos:
        names = skill_names(r["scan"])
        if names:
            per_repo.append(len(names))
        for name in names:
            job = next((j for j, pattern in SKILL_JOBS if pattern.search(name.lower())), OTHER_JOB)
            owners[job].add(r["name"])
            skills[job] += 1
    rows = [{"label": job, "repos": share(len(owners[job]), len(per_repo)), "skills": n} for job, n in skills.items()]
    rows.sort(key=lambda row: (-row["repos"]["k"], -row["skills"]))
    return {
        "rows": rows,
        "repos": len(per_repo),
        "skills": sum(skills.values()),
        "per_repo": int(statistics.median(per_repo)) if per_repo else 0,
    }


def root_pair(r, i=-1):
    """(AGENTS.md, CLAUDE.md) present at the repo root at snapshot i, or None before its history."""
    s = r["scan"]["snaps"][i]
    if s is None:
        return None
    hits = r["scan"]["sets"][s["set"]]["hits"]
    return tuple(bool(count(rule, hits.get(rule))) and hits[rule]["root"] > 0 for rule in ("agents_md", "claude_md"))


def skills_dir(scan):
    """The directory a repo keeps its skills in, following a link to the real one."""
    dirs = {
        m.group(1)
        for rule, path in scan["head_paths"]
        if rule == "skills"
        for m in [re.match(r"(.*?(?:^|/)skills?)(?:/|$)", path)]
        if m
    }
    if not dirs:
        return None
    first = min(dirs, key=lambda d: (d.count("/"), d))
    links = {l["path"]: link_target(l) for l in scan.get("links", []) if link_target(l)}
    return links.get(first, first)


def examples(repos, pick, n=5):
    """Public files worth opening: the first n repos by stars for which pick returns something."""
    out = []
    for r in sorted(repos, key=lambda r: -r["stars"]):
        found = pick(r)
        if found:
            out.append(dict(found, repo=r["name"]))
    return out[:n]


def stacked_review(pro):
    """The pro repos with an AI reviewer, and how many of them have two reviewers or more that each left two comments or more."""
    reviewed = [r for r in pro if r["now"]["ai_review"]]
    return reviewed, sum(1 for r in reviewed if sum(1 for n in r["api"]["reviewers"].values() if n >= 2) >= 2)


def cards(leagues, items, ctx, left_rows, jobs, kit_lists, build_rows, dates, shown=None):
    """One card per practice that is standard in the pro scene: meta, build, evidence, alternatives, report notes. A line of a card
    that quotes another practice is there only while that practice is on the page (`shown`; None: all)."""
    pro, ladder = leagues["pro"], leagues["ladder"]
    by = {i["id"]: i for i in items}
    if_on = lambda key, *lines: list(lines) if shown is None or key in shown else []
    gone = {row["id"]: row for row in left_rows}
    of = lambda x: "%d of %d" % (x["k"], x["n"])
    size = lambda key: [pc(in_slice(ctx["pro"], key, label)) for label in ("Small", "Mid", "Large")]
    band = lambda key: next(b["label"] for b in reversed(BANDS) if by[key]["pro"]["now"]["p"] >= b["from"])
    # the head of a note on the last BACK months: the page's words for them ("In three months", copy.back_in), not their months,
    # since the page never names the last snapshot's month: the page is dated by its issue (common.ISSUE_DATE)
    span = span_copy(BACK, SHOWN_MOVE)["back_in"]
    ev = lambda level, who, text, study=None: {
        "level": level,
        "who": who,
        "text": text,
        "src": {"label": STUDIES[study][0], "url": STUDIES[study][1]} if study else None,
    }
    has_rule = lambda rule: sum(1 for r in pro if rule_series(r, rule)[-1])

    def took_out(key, had="them", it="them"):
        row = gone[key]
        text = "%d of %d removed %s" % (row["left"]["k"], row["left"]["n"], it)
        return text + ("; " + row["after"] if "after" in row else "") + "."

    kit_top = lambda title, n: ", ".join(
        "%s (%d)" % (row["label"], row["pro"]["k"])
        for row in next(l for l in kit_lists if l["title"] == title)["rows"][:n]
    )

    # agent instruction file
    pairs_now = collections.Counter(root_pair(r) for r in pro)
    pairs_then = collections.Counter(root_pair(r, -1 - BACK) for r in pro)
    sync = collections.Counter(x for r in pro for x in sync_style(r["scan"]))
    nested = [
        sum(count(rule, h[rule]) - h[rule]["root"] for rule in ("agents_md", "claude_md") if rule in h)
        for h in (tip_tree(r)["hits"] for r in pro if r["now"]["scoped_instructions"])
    ]
    after_change = next(i for i, d in enumerate(dates) if d[:7] > "2026-09")
    small_i, _, large_i = size("instructions")

    def root_agents(r):
        files = {i["path"]: i for i in r["scan"]["instructions"] if "/" not in i["path"]}
        style, main = sync_style(r["scan"]), files.get("AGENTS.md")
        if (
            main
            and style
            and style[0] != "Two separate files"
            and not main.get("pointer_only")
            and "symlink_to" not in main
        ):
            return {"path": "AGENTS.md", "note": "%d lines" % main["lines"]}

    instructions = {
        "id": "instructions",
        "title": "Agent instruction file",
        "band": band("instructions"),
        "share": {lg: by["instructions"][lg]["now"] for lg in leagues},
        "for": "Any repo where an agent writes code: "
        "%s of the largest third of pro repos, %s of the smallest." % (large_i, small_i),
        "say": "One AGENTS.md at the root for every tool. CLAUDE.md becomes a pointer or a symlink, or goes.",
        "build": if_on(
            "agents_md",
            [
                "AGENTS.md at the root",
                "%d of %d pro repos. The median root file is %d lines long."
                % (pairs_now[(True, True)] + pairs_now[(True, False)], len(pro), median_lines(pro)),
            ],
        )
        + if_on(
            "claude_md",
            [
                "CLAUDE.md, when kept, holds nothing of its own",
                "Of %d pro repos with both at the root, %d use a pointer, %d a symlink, %d two full files."
                % (
                    sum(sync.values()),
                    sync["One just points at the other"],
                    sync["One is a symlink to the other"],
                    sync["Two separate files"],
                ),
            ],
        )
        + if_on(
            "scoped_instructions",
            [
                "One file per package in larger repos",
                "%d pro repos, a median of %d files each: %s of the largest third, %s of the smallest."
                % (
                    len(nested),
                    statistics.median(nested),
                    size("scoped_instructions")[2],
                    size("scoped_instructions")[0],
                ),
            ],
        ),
        "examples": examples(pro, root_agents),
        "evidence": [
            ev(
                "observed",
                "This panel",
                "Of the %d pro repos that had one %s or more months ago, %s removed it."
                % (
                    by["instructions"]["pro"]["kept"]["n"],
                    words(BACK),
                    by["instructions"]["pro"]["kept"]["n"] - by["instructions"]["pro"]["kept"]["k"] or "none",
                ),
            ),
            ev(
                "benchmarked",
                "Published study",
                "Across several agents and models, context files did not generally raise task success and added over 20% to inference cost. Agents did follow them.",
                "context_bench",
            ),
            ev(
                "observed",
                "Published study",
                "In 2,303 agent context files from 1,925 repos, 75.9% specify test procedures and 70.8% implementation details. Security appears in 14.8%, performance in 14.5%.",
                "agent_readmes",
            ),
        ],
        "reading": "Adoption is settled, the benefit is not: the one controlled study found no general gain and a higher bill. Its authors see a use in describing what is non-standard.",
        "alternatives": if_on(
            "claude_md",
            [
                "CLAUDE.md alone at the root",
                "%d pro repos, down from %d %s ago."
                % (pairs_now[(False, True)], pairs_then[(False, True)], months(BACK)),
            ],
            ["Two full files kept in step by hand", "%d pro repos." % sync["Two separate files"]],
        )
        + [
            [
                "Rule files for one tool",
                "Cursor rules in %d pro repos: %s Copilot instructions in %d."
                % (has_rule("cursor_rules"), took_out("cursor_rules"), has_rule("copilot_instructions")),
            ],
            [
                "No instruction file",
                "%d of %d pro repos, %d of %d on the ladder."
                % (
                    len(pro) - by["instructions"]["pro"]["now"]["k"],
                    len(pro),
                    len(ladder) - by["instructions"]["ladder"]["now"]["k"],
                    len(ladder),
                ),
            ],
        ],
        "notes": if_on("agents_md", ["Aug 2025", "AGENTS.md is published as a format shared by several tools."])
        + (
            if_on("claude_md", ["Sep 2026", "Claude Code 2.1.277 reads AGENTS.md when a folder has no CLAUDE.md."])
            if shown is None or "agents_md" in shown
            else []
        )
        # the timing over the same repos as the removals the sentence counts (removed_by)
        + if_on(
            "claude_md",
            [
                span,
                "%d pro repos removed CLAUDE.md, %d added one. %d of the removals came by the first snapshot after the change."
                % (
                    by["claude_md"]["pro"]["moves"]["lost"],
                    by["claude_md"]["pro"]["moves"]["gained"],
                    removed_by(pro, "claude_md", after_change),
                ),
            ],
        ),
    }

    # skills
    small_s, _, large_s = size("skills")
    homes = collections.Counter(
        d
        for r in pro
        for d in {p.split("/")[0] for rule, p in r["scan"]["head_paths"] if rule == "skills" and p.startswith(".")}
    )
    linked = sum(1 for r in pro if any(re.search(r"(?:^|/)skills?$", l["path"]) for l in r["scan"].get("links", [])))
    travel = travelling_skills(pro)
    how_tos = next(row for row in jobs["rows"] if row["label"] == OTHER_JOB)
    series = by["skills"]["pro"]["series"]
    at = lambda ym: series[next(i for i, d in enumerate(dates) if d[:7] >= ym)]
    half = next((d for d, p in zip(dates, series) if p >= 0.5), None)

    def skills_home(r):
        names, home = skill_names(r["scan"]), skills_dir(r["scan"])
        if home and len(names) >= 5:
            return {"path": home, "dir": True, "note": "%d skills" % len(names)}

    skills = {
        "id": "skills",
        "title": "Skills",
        "band": band("skills"),
        "share": {lg: by["skills"][lg]["now"] for lg in leagues},
        "for": "Repos where the same jobs come back: %s of the largest third of pro repos, %s of the smallest, "
        "%s of the ladder." % (large_s, small_s, pc(by["skills"]["ladder"]["now"])),
        # not "in a directory every tool can read": many pro repos with skills keep them under .claude/ only
        "say": "Skills live in the repo, in .claude/skills or the shared .agents/skills: a median of %d per pro repo with skills. "
        "%s are how-tos for the repo's own code."
        % (jobs["per_repo"], percent(share(how_tos["skills"], jobs["skills"])["p"])),
        "build": [
            [
                "A skills directory",
                ".claude/skills in %d pro repos, .agents/skills in %d. %d keep one copy and link the other names to it."
                % (homes[".claude"], homes[".agents"], linked),
            ],
            [
                "Names that travel",
                "%s are in %d or more pro repos. Nearly every other name is in one only."
                % (", ".join(travel), TRAVEL_MIN),
            ],
        ],
        "jobs": jobs["rows"],
        "jobs_note": "Share of the %d pro repos with skills that have one for the job, sorted by keywords in each name, one job per skill: a rough reading of %s skills."
        % (jobs["repos"], "{:,}".format(jobs["skills"])),
        "examples": examples(pro, skills_home),
        "evidence": [
            ev(
                "observed",
                "This panel",
                "%d of the %d pro repos that had skills %s or more months ago still do."
                % (by["skills"]["pro"]["kept"]["k"], by["skills"]["pro"]["kept"]["n"], words(BACK)),
            ),
            ev(
                "benchmarked",
                "Published study",
                "On 87 tasks and 18 model and harness setups, curated skills raised the average pass rate from 33.9% to 50.5%. Skills of at most three modules beat larger bundles.",
                "skillsbench",
            ),
            ev(
                "observed",
                "Published study",
                "In 2,853 repos, context files dominated and few repos had skills or subagents.",
                "harness",
            ),
        ],
        # not "strong retention": the instruction file is kept as well; what only skills have of the three cards is a
        # controlled result in their favour
        "reading": "The only practice here with a controlled result in its favour, for curated skills on set tasks, not any skill.",
        "alternatives": if_on(
            "commands",
            ["Custom commands", "%d pro repos. %s" % (by["commands"]["pro"]["now"]["k"], took_out("commands"))],
        )
        + if_on(
            "subagents",
            ["Custom subagents", "%d pro repos. %s" % (by["subagents"]["pro"]["now"]["k"], took_out("subagents"))],
        )
        + if_on(
            "mcp",
            [
                "MCP servers configured in the repo",
                "%d pro repos. %s" % (by["mcp"]["pro"]["now"]["k"], took_out("mcp", it="it")),
            ],
        )
        + [
            [
                "An instruction file and nothing else",
                "%d pro repos stop there." % next(b for b in build_rows if b["id"] == "briefed")["pro"]["k"],
            ],
        ],
        "notes": [
            ["Oct 2025", "Agent Skills launch. %s of the pro scene has skills that month." % pc({"p": at("2025-10")})],
            ["Dec 2025", "Skills become an open standard. %s of the pro scene has them." % pc({"p": at("2025-12")})],
        ]
        + ([[month_name(half, year=True), "Half of the pro scene now ships skills."]] if half else [])
        + [
            [
                span,
                "%d pro repos added skills and %d removed them: %s to %s of the pro scene."
                % (
                    by["skills"]["pro"]["moves"]["gained"],
                    by["skills"]["pro"]["moves"]["lost"],
                    pc({"p": by["skills"]["pro"]["series"][-1 - BACK]}),
                    pc(by["skills"]["pro"]["now"]),
                ),
            ],
        ],
    }

    # AI review on pull requests
    reviewed, several = stacked_review(pro)
    small_r, mid_r, large_r = size("ai_review")
    unseen = lambda repos: sum(1 for r in repos if not r["api"]["reviewers"])

    def review_rules(r):
        for rule, path in r["scan"]["head_paths"]:
            name = path.split("/")[-1]
            if rule == "ai_review_config" and name in REVIEW_FILES and (name != "config.json" or ".greptile/" in path):
                return {"path": path, "note": REVIEW_FILES[name]}

    review = {
        "id": "ai_review",
        "title": "AI review on pull requests",
        "band": band("ai_review"),
        "share": {lg: by["ai_review"][lg]["now"] for lg in leagues},
        "for": "Any team with a steady flow of pull requests, whatever the size: %s, %s and %s of small, mid and large pro repos. "
        "Nothing needs committing." % (small_r, mid_r, large_r),
        "say": "An AI reviewer comments before a person does. %d of the %d pro repos with one (%d comments or more) run two or more."
        % (several, len(reviewed), MIN_REVIEW_COMMENTS),
        "build": [
            [
                "A reviewer bot on the repo",
                "Most common, by pro repos: %s." % kit_top("AI reviewers on pull requests", 5),
            ],
        ]
        + if_on(
            "ai_review_config",
            [
                "Review rules in the repo, optional",
                "%d pro repos commit them: .coderabbit.yaml, REVIEW.md, BUGBOT.md, .greptile/."
                % by["ai_review_config"]["pro"]["now"]["k"],
            ],
        )
        + if_on(
            "agent_in_ci",
            [
                "Or a coding agent called from CI",
                "%d pro repos call one from a GitHub Actions workflow." % by["agent_in_ci"]["pro"]["now"]["k"],
            ],
        ),
        "examples": examples(pro, review_rules),
        "evidence": [
            ev(
                "observed",
                "This panel",
                "%s pro repos had %d or more of their latest %d review or pull request comments left by AI "
                "reviewers, %s ladder repos."
                % (
                    of(by["ai_review"]["pro"]["now"]),
                    MIN_REVIEW_COMMENTS,
                    LATEST_ITEMS,
                    of(by["ai_review"]["ladder"]["now"]),
                ),
            ),
            ev(
                "observed",
                "Published study",
                "Among 3,109 pull requests, 45.2% of those reviewed only by an AI agent were merged, against 68.4% of those reviewed only by people. 12 of 13 agents averaged a signal ratio under 60%.",
                "review_agents",
            ),
            ev(
                "observed",
                "Published study",
                "In one company's rollout, 73.8% of automated review comments were resolved, and the average time to close a pull request rose from 5 h 52 to 8 h 20.",
                "review_practice",
            ),
        ],
        "reading": "A mixed published record: most bot comments get resolved, but pull requests closed slower and bot-only review goes with fewer merges. Nothing here supports dropping the human reviewer.",
        "alternatives": if_on(
            "agent_in_ci",
            [
                "A coding agent in CI",
                "%d pro repos. %s" % (by["agent_in_ci"]["pro"]["now"]["k"], took_out("agent_in_ci", it="it")),
            ],
        )
        + if_on(
            "ai_review_config",
            [
                "Rules committed, no reviewer seen",
                "%d pro repos." % sum(1 for r in pro if r["now"]["ai_review_config"] and not r["now"]["ai_review"]),
            ],
        )
        + [
            # no comment at all from an AI reviewer: a repo under the practice's threshold may have one or two
            [
                "No AI review seen",
                "%d of %d pro repos, %d of %d on the ladder." % (unseen(pro), len(pro), unseen(ladder), len(ladder)),
            ],
        ],
        "notes": if_on(
            "ai_review_config",
            [
                month_name(dates[0], year=True),
                "%s of the pro scene has review rules committed. Today %s does."
                % (pc({"p": by["ai_review_config"]["pro"]["series"][0]}), pc(by["ai_review_config"]["pro"]["now"])),
            ],
        )
        + [["Today only", "Reviewer bots are read from recent pull requests, so they have no history."]],
    }
    return [instructions, skills, review]


# The practices a reading names beside its own, by the row it is written for: a reading is kept only while they are on the page
# The instruction file's reading of What left names the instruction files dropped, which it checks itself.
READING_NAMES = {
    "move": {
        "multi_tool": {"claude_md", "agents_md"},
        "scoped_instructions": {"agents_md", "claude_md"},
        "agents_md": {"claude_md"},
        "claude_md": {"agents_md"},
        "agents_dir": {"skills"},
        "shared_settings": {"claude_md"},
        "adr": {"skills"},
        "agent_commits": {"agent_prs"},
        "ai_review_config": {"ai_review"},
    },
    "stay": {
        "agents_md": {"claude_md"},
        "claude_md": {"agents_md"},
        "commands": {"skills"},
        "mcp": {"skills"},
        "hooks": {"claude_md"},
        "agent_in_ci": {"agent_commits", "agent_prs"},
        "ai_review_config": {"ai_review"},
    },
}
# The practice a row's "after" names (what its leavers have today): LEFT_FOR's, and those of the lens rows
AFTER_NAMES = dict(
    {key: feature for key, (feature, _) in LEFT_FOR.items()}, fence_tools="agent_in_ci", eslint="fast_lint"
)
AFTER_NAMES["prettier"] = "fast_lint"


def readings(leagues, items, left_rows, dates, shown=None):
    """Our reading of each row of What moved and of the removal ranking, as two dicts by id.

    A reading interprets what was counted: what the movers or the leavers have, and when. It
    never says that a practice works. Each one is written only while the fact it rests on holds;
    a row with nothing sound to say gets None. The What moved reading is about the last three
    months, the removal one about the whole history, and a row does not say the same thing twice.
    """
    pro = leagues["pro"]
    by = {i["id"]: i for i in items}
    gone = {row["id"]: row for row in left_rows}
    then = -1 - BACK
    tool_rules = {rule for rule, _ in TOOL_FILES}
    names = dict(LABEL, **dict(TOOL_FILES))
    month_long = lambda iso: AS_OF.replace(year=int(iso[:4]), month=int(iso[5:7]), day=1).strftime("%B %Y")
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    cap = lambda text: text[0].upper() + text[1:]
    first = lambda r, key: next((i for i, f in enumerate(r["f"]) if f and f[key]), None)
    ever_had = lambda r, key: first(r, key) is not None

    def moved(key):
        """Pro repos that added and that removed a practice over the last BACK snapshots, as moves() counts them:
        a repo created since that has it today is among those that added it."""
        pairs = [(r, r["f"][then], r["f"][-1]) for r in pro]
        return (
            [r for r, a, b in pairs if b[key] and not has(a, key)],
            [r for r, a, b in pairs if has(a, key) and not b[key]],
        )

    def leavers(key):
        """Pro repos that had a practice at an earlier snapshot and not today, with the last snapshot they had it."""
        series_of = (lambda r: rule_series(r, key)) if key in tool_rules else (lambda r: [f and f[key] for f in r["f"]])
        _, out, _ = departures(pro, series_of)
        return [(r, max(i for i, x in enumerate(series_of(r)) if x)) for r in out]

    def below_root(r, rule):
        h = tip_tree(r)["hits"].get(rule)
        return bool(h) and count(rule, h) > h["root"]

    def defers(r):
        """The repo's CLAUDE.md files all point or link to an AGENTS.md."""
        files = [i for i in r["scan"]["instructions"] if i["rule"] == "claude_md"]
        return bool(files) and all(
            (i.get("symlink_to") or "").endswith("AGENTS.md")
            or (i.get("pointer_only") and any(x.endswith("AGENTS.md") for x in i.get("imports", [])))
            for i in files
        )

    dropped_claude = lambda r: has(r["f"][then], "claude_md") and not r["now"]["claude_md"]
    move, stay = {}, {}

    # ---------- What moved: the last three months
    added, removed = moved("multi_tool")
    via = [r for r in removed if dropped_claude(r)]
    if removed and 2 * len(via) > len(removed):
        kept = sum(1 for r in via if r["now"]["agents_md"])
        move["multi_tool"] = "%s that lost it removed their CLAUDE.md%s: the same move, seen from the other side." % (
            cap(of_the(len(via), len(removed))),
            " and kept an AGENTS.md" if kept == len(via) else ", and %d of those kept an AGENTS.md" % kept,
        )

    added, _ = moved("scoped_instructions")
    as_agents = sum(1 for r in added if below_root(r, "agents_md"))
    as_claude = sum(1 for r in added if below_root(r, "claude_md"))
    if added and 2 * as_agents > len(added):
        move["scoped_instructions"] = "%s repos that added per-package files wrote them as AGENTS.md%s." % (
            cap(of_the(as_agents, len(added))),
            ", and %d also keep%s a CLAUDE.md below the root" % (as_claude, "s" if as_claude == 1 else "")
            if as_claude
            else "",
        )

    added, _ = moved("agents_md")
    had = [r for r in added if has(r["f"][then], "claude_md")]
    both = sum(1 for r in had if r["now"]["claude_md"])
    if added and 2 * len(had) > len(added) and 2 * both > len(had):
        move["agents_md"] = (
            "%s that added it had a CLAUDE.md and %d keep both: it arrives beside the old file more often than in its place."
            % (cap(of_the(len(had), len(added))), both)
        )

    added, removed = moved("claude_md")
    landed = sum(1 for r in removed if r["now"]["agents_md"])
    pointing = sum(1 for r in added if defers(r))
    if removed and 2 * landed > len(removed) and added and 2 * pointing > len(added):
        # the timing against the Claude Code release is already in the section's intro (copy.moves)
        move["claude_md"] = (
            "%s repos that removed it have an AGENTS.md, and %s that added one made it a pointer to AGENTS.md."
            % (cap(of_the(landed, len(removed))), of_the(pointing, len(added)))
        )

    def skills_inside(r):
        return any(rule == "skills" and p.startswith(".agents/") for rule, p in r["scan"]["head_paths"]) or any(
            l["path"].startswith(".agents/skill") for l in r["scan"].get("links", [])
        )

    added, _ = moved("agents_dir")
    with_dir = [r for r in pro if r["now"]["agents_dir"]]
    inside = sum(1 for r in with_dir if skills_inside(r))
    if with_dir and 2 * inside > len(with_dir):
        move["agents_dir"] = "Mostly a home for skills: %d of the %d pro repos with one keep skills in it%s." % (
            inside,
            len(with_dir),
            ", as do %s that added one" % of_the(sum(1 for r in added if skills_inside(r)), len(added))
            if added
            else "",
        )

    # the repos that added skills in each window of three months, as moves() counts them: a repo created since counts
    gains = [
        sum(1 for r in pro if has(r["f"][i], "skills") and not has(r["f"][i - BACK], "skills"))
        for i in range(BACK, len(dates))
    ]
    peak = max(range(len(gains)), key=lambda j: gains[j])
    if 2 * gains[-1] < gains[peak]:
        move["skills"] = "Uptake has slowed: %d repos added skills in %s, against %d at the peak, in the %s to %s." % (
            gains[-1],
            months(BACK),
            gains[peak],
            months(BACK),
            month_long(dates[peak + BACK]),
        )

    _, removed = moved("shared_settings")
    with_claude = sum(1 for r in removed if dropped_claude(r))
    if removed and 2 * with_claude > len(removed):
        move["shared_settings"] = (
            "%s repos that dropped them also removed their CLAUDE.md: the settings went with it, not on their own."
            % (cap(of_the(with_claude, len(removed))))
        )

    added, _ = moved("adr")
    with_skills = sum(1 for r in added if r["now"]["skills"])
    base = by["skills"]["pro"]["now"]
    if added and with_skills / len(added) > base["p"]:
        move["adr"] = (
            "Rising where agents are set up: %s repos that added decision records ship skills, against %d of %d across the pro scene."
            % (of_the(with_skills, len(added)), base["k"], base["n"])
        )

    _, removed = moved("agent_commits")
    prs = sum(1 for r in removed if r["now"]["agent_prs"])
    quieter = sum(
        1
        for r in removed
        if r["scan"]["snaps"][-1]["commits90"]["total"] < r["scan"]["snaps"][then]["commits90"]["total"]
    )
    if removed and 2 * prs > len(removed) and quieter:
        move["agent_commits"] = (
            "%s that fell below %d signed commits in %d days still have agent-opened pull requests, and %d committed less overall."
            % (cap(of_the(prs, len(removed))), MIN_SIGNED_COMMITS, COMMIT_DAYS, quieter)
        )

    added, _ = moved("ai_review_config")
    reviewed = sum(1 for r in added if r["now"]["ai_review"])
    review_md = sum(1 for r in added if ["ai_review_config", "REVIEW.md"] in r["scan"]["head_paths"])
    if added and 2 * reviewed > len(added):
        move["ai_review_config"] = (
            "Rules follow the reviewer: %s that added them have an AI reviewer today, and %d wrote them as a REVIEW.md at the root."
            % (of_the(reviewed, len(added)), review_md)
        )

    # ---------- What left, what stayed: since the first snapshot
    had = [r for r in pro if any(f and f["instructions"] for f in r["f"])]
    swapped, renamed = collections.Counter(), 0
    for r in had:
        lost = [rule for rule in fp.INSTRUCTION_RULES for s in [rule_series(r, rule)] if any(s[:-1]) and not s[-1]]
        if lost and r["now"]["instructions"]:
            renamed += 1
            swapped.update(lost)
    # the files it names are practices too (CLAUDE.md, AGENTS.md) or files of one tool, which What left always shows
    if renamed and all(shown is None or rule in shown or rule not in PRACTICES for rule, _ in swapped.most_common(2)):
        stay["instructions"] = (
            "The file stays, its name changes: %d of the %d dropped one instruction file and kept another, most often %s."
            % (renamed, len(had), " or ".join(names[rule] for rule, _ in swapped.most_common(2)))
        )

    moved_out = {r["name"]: r for key in ["claude_md"] + sorted(tool_rules) for r, _ in leavers(key)}
    landed = sum(1 for r in moved_out.values() if r["now"]["agents_md"])
    if moved_out and 2 * landed > len(moved_out):
        out = leavers("agents_md")
        stay["agents_md"] = "%s that removed CLAUDE.md or another tool's file have it%s." % (
            cap(of_the(landed, len(moved_out))),
            ", and the one leaver, gone by %s, keeps a CLAUDE.md" % month_long(dates[out[0][1] + 1])
            if len(out) == 1 and out[0][0]["now"]["claude_md"]
            else "",
        )

    row = gone["claude_md"]
    start = next((i for i, c in enumerate(row["when"]) if c), None)
    keepers = [r for r in pro if r["now"]["claude_md"]]
    if start is not None and start > len(dates) // 2:
        stay["claude_md"] = (
            "No removal through %s, then all %d in the %d snapshots after, and %d of the %d that keep one only point or link to AGENTS.md."
            % (
                month_long(dates[start - 1]),
                row["left"]["k"],
                len(dates) - start,
                sum(1 for r in keepers if defers(r)),
                len(keepers),
            )
        )

    had = [r for r in pro if any(f and f["skills"] for f in r["f"])]
    recent = sum(1 for r in had if dates[first(r, "skills")][:4] == str(AS_OF.year))
    if had and 2 * recent > len(had):
        stay["skills"] = "A short record: %d of the %d that ever had skills first show them in %d." % (
            recent,
            len(had),
            AS_OF.year,
        )

    out = leavers("commands")
    ahead = [last - first(r, "skills") for r, last in out if r["f"][last]["skills"]]  # pyright: ignore[reportOperatorIssue]  (skills at last, so first() is a number)
    if out and len(ahead) == len(out):
        stay["commands"] = "%s that removed them had shipped skills first, for a median of %g months." % (
            cap(of_the(len(out), len(out))),
            statistics.median(ahead),
        )

    out = leavers("mcp")
    no_skills = sum(1 for r, _ in out if not ever_had(r, "skills"))
    busiest = max(gone["mcp"]["when"])
    if out and 3 * busiest <= len(out) and no_skills:
        stay["mcp"] = (
            "%d of the %d leavers never had skills, and a server set up on a laptop leaves no trace, so the use may outlast the file."
            % (no_skills, len(out))
        )

    row = gone["hooks"]
    kept = row["left"]["n"] - row["left"]["k"]
    out = leavers("hooks")
    with_claude = sum(1 for r, _ in out if ever_had(r, "claude_md") and not r["now"]["claude_md"])
    if 2 * kept > row["left"]["n"]:
        stay["hooks"] = "Hooks run code, so keeping them is a choice: %d of the %d that had them still do%s." % (
            kept,
            row["left"]["n"],
            ", and %d of the %d leavers dropped CLAUDE.md too" % (with_claude, len(out))
            if 2 * with_claude > len(out)
            else "",
        )

    out = leavers("agent_in_ci")
    busy = sum(1 for r, _ in out if r["now"]["agent_commits"] or r["now"]["agent_prs"])
    if out and 2 * busy > len(out):
        stay["agent_in_ci"] = (
            "%s that took it out still have agents signing commits or opening pull requests; whether an AI reviewer replaced it is unknown."
            % (cap(of_the(busy, len(out))))
        )

    out = leavers("ai_review_config")
    reviewed = sum(1 for r, _ in out if r["now"]["ai_review"])
    if out and 2 * reviewed > len(out):
        stay["ai_review_config"] = (
            "The rules are the optional part: %s that removed them still have an AI reviewer on pull requests."
            % (of_the(reviewed, len(out)))
        )

    out = leavers("cursor_rules")
    signing = sum(1 for r, _ in out if r["scan"]["snaps"][-1]["commits90"]["by"].get("cursor", 0) >= 1)
    # not "a lower bound, since it only signs from February 2026": the scans hold Cursor-signed commits from mid-2025
    if out and 2 * signing > len(out):
        stay["cursor_rules"] = "The tool stayed, its rules went: %d of the %d have Cursor signing commits today." % (
            signing,
            len(out),
        )

    # only for the rows the page shows, and only while the practices a reading names are on the page
    named = lambda kind, k: shown is None or READING_NAMES[kind].get(k, set()) <= set(shown)
    move = {k: v for k, v in move.items() if named("move", k)}
    stay = {k: v for k, v in stay.items() if named("stay", k)}
    move = {k: v for k, v in move.items() if by[k]["history"] and shown_move(by[k]["pro"]["moves"])}
    stay = {k: v for k, v in stay.items() if in_left(gone[k]) or in_stayed(gone[k])}
    for text in list(move.values()) + list(stay.values()):
        if len(text) > READING_MAX:
            raise ValueError("reading over %d characters (%d): %s" % (READING_MAX, len(text), text))
    return move, stay


# ---------- The Insight of a practice's row in Build and Ship
# One sentence per row, under the rules of readings(): what the pro repos with the practice also have, what they are made of, how
# they spread over size, language or time. Each reader returns None when the fact it rests on does not hold or its base is too
# small; row_readings() drops a reading whose row, or a practice it names beside its own (ROW_NAMES), is off the page. A row's
# reading goes to Build's `reading` (beside the cards') or to the practice's own `reading` in the other sections (main()).
ROW_NAMES = {
    "compose_dev": {"env_example"},
    "agent_in_ci": {"app_token"},
    "agent_prs": {"instructions"},
    "commands": {"skills"},
    "multi_arch_images": {"container_images"},
    "preview_deploys": {"deploy_cloud"},
    "container_images": {"signed_builds"},
    "deploy_cloud": {"container_images"},
}
# The outside facts three readings state, each in the source's words (read on 2026-11-24): the sentence says no more than these
ROW_SOURCES = {
    "stale_bot": (
        "https://github.com/probot/stale",
        "This repository was archived by the owner on May 20, 2023. It is now read-only. "
        "The stale app is deprecated and this repository is no longer maintained",
    ),
    "commands": (
        "https://code.claude.com/docs/en/slash-commands",
        "Custom commands have been merged into skills. Your existing `.claude/commands/` files keep working.",
    ),
    "environments": (
        "https://docs.pypi.org/trusted-publishers/adding-a-publisher/",
        "Configuring an environment is optional, but strongly recommended",
    ),
}
MCP_BROWSERS = {"playwright", "chrome-devtools", "puppeteer"}
# the words of a repo's or owner's name too common to tell a product's own MCP server (a token of 4 letters or more)
MCP_COMMON = {"labs", "core", "team", "chat", "tools", "server", "docs"}


def _of_the(k, n):
    return "all %d" % n if k == n else "%d of the %d" % (k, n)


def _cap(text):
    return text[0].upper() + text[1:]


def _with(rows, key):
    return [r for r in rows if r["now"][key]]


def _tip(r):
    return r["scan"]["snaps"][-1]


def _sample(r, rule):
    """The paths of one rule the scan kept at the tip, those that still count when it kept all of them (count())."""
    h = tip_tree(r)["hits"].get(rule)
    if not h or not h["n"]:
        return []
    return h["sample"] if h["n"] > len(h["sample"]) else [p for p in h["sample"] if fp.still_valid(rule, p)]


def _base_names(r, *rules):
    return {p.split("/")[-1].lower() for rule in rules for p in _sample(r, rule)}


def _ci(r, key, i=-1):
    return key in ((r["scan"]["snaps"][i] or {}).get("ops") or {}).get("ci", ())


def _hits_at(r, rule, i):
    """Hits of one rule at snapshot i, 0 when the repo had no state then."""
    s = r["scan"]["snaps"][i]
    return count(rule, r["scan"]["sets"][s["set"]]["hits"].get(rule)) if s else 0


def _lens_now(r):
    return r["g"][-1] or {}


def _mono(r):
    return bool(WORKSPACE & set(tip_tree(r)["root"]))


def _lang(r):
    return LANGUAGES.get(r["language"], "Other")


def _thirds(rows):
    """The size third of each repo, 0 to 2, as contexts() cuts them (own_files)."""
    sizes = sorted(own_files(r) for r in rows)
    small, large = sizes[len(sizes) // 3], sizes[2 * len(sizes) // 3]
    return lambda r: 0 if own_files(r) < small else 1 if own_files(r) < large else 2


def _pair(pro, key, test):
    """Of the pro repos with a practice and of the others, how many pass `test`: (a, n, b, m)."""
    rows, rest = _with(pro, key), [r for r in pro if not r["now"][key]]
    return sum(1 for r in rows if test(r)), len(rows), sum(1 for r in rest if test(r)), len(rest)


def _twice(a, n, b, m):
    """The holders' share is twice the others' or more, both bases non-empty."""
    return n > 0 and m > 0 and a * m >= 2 * b * n


def _read_mcp(pro, lad, dates):
    rows = _with(pro, "mcp")
    servers = {r["name"]: [s.lower() for s in _tip(r).get("mcp") or []] for r in rows}

    def tokens(name):
        owner, repo = name.lower().split("/")
        words = set(re.split(r"[-_.]", owner)) | set(re.split(r"[-_.]", repo)) | {owner, repo}
        return {w for w in words if len(w) >= 4 and w not in MCP_COMMON}

    own = [r for r in rows if any(t in s for s in servers[r["name"]] for t in tokens(r["name"]))]
    docs = sum(1 for r in own if any("docs" in s for s in servers[r["name"]]))
    browser = sum(1 for r in rows if MCP_BROWSERS & set(servers[r["name"]]))
    if len(rows) >= MIN_BASE and 2 * len(own) > len(rows):
        # the docs servers among the own, said while they are 3 or more, and dropped before the browsers to keep the cap
        text = lambda docs_clause: (
            "%s name an MCP server of their own product%s; %d a browser, Playwright or Chrome DevTools."
            % (  # noqa: E731
                _cap(_of_the(len(own), len(rows))),
                docs_clause,
                browser,
            )
        )
        long = text(", %d of them its docs" % docs) if docs >= 3 else ""
        return long if long and len(long) <= READING_MAX else text("")


def _read_patched_deps(pro, lad, dates):
    rows = _with(pro, "patched_deps")
    pnpm = [r for r in pro if ((_tip(r).get("sec") or {}).get("manager") or [None])[0] == "pnpm"]
    mono, patched = sum(1 for r in rows if _mono(r)), sum(1 for r in pnpm if r["now"]["patched_deps"])
    if rows and 4 * mono >= 3 * len(rows) and len(pnpm) >= MIN_BASE:
        return (
            "%s are monorepos. %d of the %d pro repos that name pnpm as their package manager patch a dependency."
            % (
                _cap(_of_the(mono, len(rows))),
                patched,
                len(pnpm),
            )
        )


def _read_compose_dev(pro, lad, dates):
    a, n, b, m = _pair(pro, "compose_dev", lambda r: r["now"]["env_example"])
    if _twice(a, n, b, m):
        return "%s also commit an example settings file, against %d of the %d repos without one." % (
            _cap(_of_the(a, n)),
            b,
            m,
        )


def _read_agent_in_ci(pro, lad, dates):
    a, n, b, m = _pair(pro, "agent_in_ci", lambda r: r["now"]["app_token"])
    if _twice(a, n, b, m):
        return (
            "%s also act as a GitHub App in CI, with a token of its own, against %d of the %d without an agent there."
            % (
                _cap(_of_the(a, n)),
                b,
                m,
            )
        )


def _read_agent_prs(pro, lad, dates):
    third = _thirds(pro)
    cells = [[r for r in pro if third(r) == i] for i in range(3)]
    if min(map(len, cells)) < MIN_BASE:
        return None
    prs = [sum(1 for r in c if r["now"]["agent_prs"]) / len(c) for c in cells]
    told = [sum(1 for r in c if r["now"]["instructions"]) / len(c) for c in cells]
    # the spread of the three as the page prints them, 10 points or less; the instruction file up 20 points or more
    if max(map(points, prs)) - min(map(points, prs)) <= 10 and points(told[2]) - points(told[0]) >= 20:
        return (
            "Flat across sizes: %s, %s and %s of the three size thirds, where the instruction file goes from %s to %s."
            % (
                percent(prs[0]),
                percent(prs[1]),
                percent(prs[2]),
                percent(told[0]),
                percent(told[2]),
            )
        )


def _read_stale_bot(pro, lad, dates):
    rows = _with(pro, "stale_bot")
    action = sum(1 for r in rows if _ci(r, "stale"))
    probot = sum(1 for r in rows if _hits_at(r, "stale_config", -1) > 0 and not _ci(r, "stale"))
    if rows and probot >= 3:
        return (
            "%s run actions/stale. %d keep only a .github/stale.yml, the config of Probot's Stale app, deprecated since May 2023."
            % (
                _cap(_of_the(action, len(rows))),
                probot,
            )
        )


def _read_hooks(pro, lad, dates):
    rows = _with(pro, "hooks")
    runs = [r for r in rows if _lens_now(r).get("hook_runs")]
    heavy = sum(1 for r in runs if {"tests", "types"} & _lens_now(r)["hook_runs"])
    light = sum(1 for r in runs if {"format", "lint"} & _lens_now(r)["hook_runs"])
    guard = sum(1 for r in rows if _lens_now(r).get("guard_hook"))
    if runs and not heavy and 2 * light > len(runs):
        return (
            "%d of the %d run a check from a hook, mostly a formatter or a linter, never the tests or a type check; %d can block an action."
            % (
                len(runs),
                len(rows),
                guard,
            )
        )


def _read_agent_commits(pro, lad, dates):
    signers = lambda r: sum(1 for v in _tip(r)["commits90"]["by"].values() if v >= 1)
    rows, lrows = _with(pro, "agent_commits"), _with(lad, "agent_commits")
    if not rows or not lrows:
        return None
    two, ltwo = sum(1 for r in rows if signers(r) >= 2), sum(1 for r in lrows if signers(r) >= 2)
    c = lambda r: _tip(r)["commits90"]
    median = statistics.median(c(r)["signed"] / c(r)["total"] if c(r)["total"] else 0 for r in rows)
    if len(rows) >= MIN_BASE and two * len(lrows) > ltwo * len(rows):
        return (
            "%d of the %d carry the signatures of two agents or more, %d of the %d on the ladder. In the median one, %s of commits are signed."
            % (
                two,
                len(rows),
                ltwo,
                len(lrows),
                percent(median),
            )
        )


def _read_commands(pro, lad, dates):
    rows = _with(pro, "commands")
    _, out, _ = departures(pro, lambda r: [f and f["commands"] for f in r["f"]])
    skills, out_skills = sum(1 for r in rows if r["now"]["skills"]), sum(1 for r in out if r["now"]["skills"])
    if rows and out and 2 * out_skills > len(out):
        return (
            "%s also have skills, as do %d of the %d that took commands out: Claude Code has merged its commands into skills."
            % (
                _cap(_of_the(skills, len(rows))),
                out_skills,
                len(out),
            )
        )


def _read_adr(pro, lad, dates):
    ps = [sum(1 for r in pro if has(r["f"][i], "adr")) for i in range(len(dates))]
    ls = [sum(1 for r in lad if has(r["f"][i], "adr")) for i in range(len(dates))]
    # the snapshot before the pro scene's steepest month: where its rise starts
    j = max(range(len(ps) - 1), key=lambda i: (ps[i + 1] - ps[i], -i))
    if ls[0] > ps[0] and ps[-1] - ps[j] >= 5:
        return (
            "The ladder had them first: %d ladder repos and %d pro in %s. The pro scene went from %d to %d since %s."
            % (
                ls[0],
                ps[0],
                month_name(dates[0], year=True, full=True),
                ps[j],
                ps[-1],
                month_name(dates[j], year=True, full=True),
            )
        )


def _read_task_runner(pro, lad, dates):
    rows = _with(pro, "task_runner")
    make = sum(1 for r in rows if _base_names(r, "task_runner") & {"makefile", "gnumakefile"})
    just = sum(1 for r in rows if _base_names(r, "task_runner") & {"justfile", ".justfile"})
    gr, js = [r for r in pro if _lang(r) == "Go or Rust"], [r for r in pro if _lang(r) == "TypeScript or JS"]
    if rows and len(gr) >= MIN_BASE and len(js) >= MIN_BASE:
        return (
            "%d of the %d are a Makefile, %d a justfile. %d of the %d Go or Rust repos have one, %d of the %d in TypeScript or JS."
            % (
                make,
                len(rows),
                just,
                sum(1 for r in gr if r["now"]["task_runner"]),
                len(gr),
                sum(1 for r in js if r["now"]["task_runner"]),
                len(js),
            )
        )


def _read_toolchain_pinned(pro, lad, dates):
    rows = _with(pro, "toolchain_pinned")
    names = lambda r: _base_names(r, "toolchain_files", "toolchain_other")
    manager = sum(1 for r in rows if (_tip(r).get("sec") or {}).get("manager"))
    nvm = sum(1 for r in rows if ".nvmrc" in names(r))
    rust = sum(1 for r in rows if names(r) & {"rust-toolchain", "rust-toolchain.toml"})
    if rows and manager > nvm:
        return "%d of the %d set packageManager in package.json, %d keep an .nvmrc, %d a rust-toolchain file." % (
            manager,
            len(rows),
            nvm,
            rust,
        )


def _read_issue_forms(pro, lad, dates):
    form = lambda r: any(
        p.lower().endswith((".yml", ".yaml")) and not p.lower().endswith(("config.yml", "config.yaml"))
        for p in _sample(r, "issue_templates")
    )
    rows, lrows = _with(pro, "issue_forms"), _with(lad, "issue_forms")
    a, b = sum(1 for r in rows if form(r)), sum(1 for r in lrows if form(r))
    # the pro share 10 points or more above the ladder's
    if rows and len(lrows) >= MIN_BASE and 10 * a * len(lrows) >= 10 * b * len(rows) + len(rows) * len(lrows):
        return "%d of the %d use YAML forms, not Markdown alone; on the ladder %d of the %d." % (
            a,
            len(rows),
            b,
            len(lrows),
        )


def _read_dev_env_declared(pro, lad, dates):
    rows = _with(pro, "dev_env_declared")
    nix = [sum(1 for r in pro if _hits_at(r, "nix_env", i) > 0) for i in (0, -1)]
    container = sum(1 for r in rows if _hits_at(r, "devcontainer", -1) > 0)
    # "nearly doubled": 1.6 times or more, and less than twice
    if rows and nix[0] and 5 * nix[1] >= 8 * nix[0] and nix[1] < 2 * nix[0]:
        return "%d of the %d use a dev container, %d Nix. Nix nearly doubled: %d pro repos in %s, %d today." % (
            container,
            len(rows),
            nix[1],
            nix[0],
            month_name(dates[0], year=True, full=True),
            nix[1],
        )


def _docs_tools(r):
    """The docs tools of a repo's docs site, by the files the scan kept: Mintlify's docs.json and mint.json, Sphinx's conf.py,
    MkDocs, Docusaurus, Read the Docs; any other file by its rule and name."""
    out = set()
    for rule in ("docs_site", "docs_json", "docs_other"):
        for p in _sample(r, rule):
            f = p.split("/")[-1].lower()
            out.add(
                "mintlify"
                if rule == "docs_json" or f == "mint.json"
                else "sphinx"
                if f == "conf.py"
                else "mkdocs"
                if "mkdocs" in f
                else "docusaurus"
                if "docusaurus" in f
                else "readthedocs"
                if "readthedocs" in f
                else rule + ":" + f
            )
    return out


def _read_docs_site(pro, lad, dates):
    tally = lambda rows: collections.Counter(t for r in rows for t in _docs_tools(r))
    rows, lrows = _with(pro, "docs_site"), _with(lad, "docs_site")
    p, l = tally(rows), tally(lrows)
    if not p or not l:
        return None
    top = lambda c: [t for t, _ in sorted(c.items(), key=lambda x: -x[1])[:2]]
    if top(p)[0] == "mintlify" and 4 * l["mintlify"] < p["mintlify"] and set(top(l)) == {"sphinx", "mkdocs"}:
        return "Mintlify leads here: %d of the %d. The ladder has %s; it builds with Sphinx (%d) and MkDocs (%d)." % (
            p["mintlify"],
            len(rows),
            "none" if not l["mintlify"] else "%d" % l["mintlify"],
            l["sphinx"],
            l["mkdocs"],
        )


def _read_multi_arch_images(pro, lad, dates):
    push, lpush = _with(pro, "container_images"), _with(lad, "container_images")
    a, b = sum(1 for r in push if r["now"]["multi_arch_images"]), sum(1 for r in lpush if r["now"]["multi_arch_images"])
    # both bases 20 or more, and the pro share 15 points or more above the ladder's
    if (
        len(push) >= MIN_BASE
        and len(lpush) >= MIN_BASE
        and 100 * a * len(lpush) > 100 * b * len(push) + 15 * len(push) * len(lpush)
    ):
        return "%d of the %d repos that push images build them for ARM as well; on the ladder %d of the %d." % (
            a,
            len(push),
            b,
            len(lpush),
        )


def _read_change_convention(pro, lad, dates):
    rows = _with(pro, "change_convention")
    lint = lambda r: (
        _hits_at(r, "commit_convention", -1) > 0 or "commitlint" in ((_tip(r).get("ops") or {}).get("pkg") or ())
    )
    title = sum(1 for r in rows if _ci(r, "title_check"))
    only = sum(1 for r in rows if _ci(r, "title_check") and not lint(r))
    commitlint = sum(1 for r in rows if lint(r))
    if rows and title > commitlint:
        return (
            "The check is on the pull request title in %d of the %d, %d with nothing else; %d run commitlint on commits."
            % (
                title,
                len(rows),
                only,
                commitlint,
            )
        )


def _read_preview_deploys(pro, lad, dates):
    rows = _with(pro, "preview_deploys")
    hosts = collections.Counter(h for r in rows for h in r["api"]["preview_hosts"])
    deploy = sum(1 for r in rows if r["now"]["deploy_cloud"])
    # Vercel's bot the most frequent. Cloudflare's, second, is not named: the page keeps the name of its own host out of
    # its text
    if hosts and hosts.most_common(1)[0][0] == "Vercel" and 3 * deploy < len(rows):
        return "Vercel's bot posts in %d of the %d. Only %d of the %d deploy from a workflow too." % (
            hosts["Vercel"],
            len(rows),
            deploy,
            len(rows),
        )


def _read_environments(pro, lad, dates):
    py, other = [r for r in pro if _lang(r) == "Python"], [r for r in pro if _lang(r) != "Python"]
    a, b = sum(1 for r in py if r["now"]["environments"]), sum(1 for r in other if r["now"]["environments"])
    # a Python base of 20 or more, and its share 1.5 times the others' or more
    if len(py) >= MIN_BASE and other and 2 * a * len(other) >= 3 * b * len(py):
        return (
            "Python leads: %d of the %d Python repos, %d of the %d others. PyPI calls one strongly recommended for trusted publishing."
            % (
                a,
                len(py),
                b,
                len(other),
            )
        )


def _read_container_images(pro, lad, dates):
    a, n, b, m = _pair(pro, "container_images", lambda r: _lens_now(r).get("signed_builds"))
    if _twice(a, n, b, m):
        return "%s sign or attest what they build, against %d of the %d that push no image." % (
            _cap(_of_the(a, n)),
            b,
            m,
        )


def _read_deploy_cloud(pro, lad, dates):
    a, n, b, m = _pair(pro, "deploy_cloud", lambda r: r["now"]["container_images"])
    # a base of 20 or more, and the share 1.5 times the others' or more
    if n >= MIN_BASE and m and 2 * a * m >= 3 * b * n:
        return "%s also push container images, against %d of the %d that deploy nothing from CI." % (
            _cap(_of_the(a, n)),
            b,
            m,
        )


ROW_READS = {
    "mcp": _read_mcp,
    "patched_deps": _read_patched_deps,
    "compose_dev": _read_compose_dev,
    "agent_in_ci": _read_agent_in_ci,
    "agent_prs": _read_agent_prs,
    "stale_bot": _read_stale_bot,
    "hooks": _read_hooks,
    "agent_commits": _read_agent_commits,
    "commands": _read_commands,
    "adr": _read_adr,
    "task_runner": _read_task_runner,
    "toolchain_pinned": _read_toolchain_pinned,
    "issue_forms": _read_issue_forms,
    "dev_env_declared": _read_dev_env_declared,
    "docs_site": _read_docs_site,
    "multi_arch_images": _read_multi_arch_images,
    "change_convention": _read_change_convention,
    "preview_deploys": _read_preview_deploys,
    "environments": _read_environments,
    "container_images": _read_container_images,
    "deploy_cloud": _read_deploy_cloud,
}


def row_readings(leagues, dates, shown=None):
    """The Insight of a practice's row in Build and Ship, by id: each reader's sentence, kept only while the row and every practice
    it names (ROW_NAMES) are on the page (`shown`; None: all)."""
    out = {}
    for key, read in ROW_READS.items():
        if shown is not None and not ({key} | ROW_NAMES.get(key, set())) <= set(shown):
            continue
        text = read(leagues["pro"], leagues["ladder"], dates)
        if text is None:
            continue
        if len(text) > READING_MAX:
            raise ValueError("reading over %d characters (%d): %s" % (READING_MAX, len(text), text))
        out[key] = text
    return out


def evidence(studies, practices, leagues):
    """The four evidence levels, with what this page holds at each: every practice on the page, of every section (as the Method's
    summary counts them; the candidates under the bar are not counted) and the studies of their outside evidence."""
    cited = {level: {e["src"]["url"] for e in studies if e["level"] == level} for level, _, _ in LEVELS}
    here = {
        "observed": "%d practices in %d repos, and %d published studies"
        % (practices, sum(len(repos) for repos in leagues.values()), len(cited["observed"])),
        "benchmarked": "%d published studies, none of ours" % len(cited["benchmarked"]),
    }
    return [
        {"id": level, "asks": asks, "what": what, "here": here.get(level, "Nothing yet")}
        for level, asks, what in LEVELS
    ]


def month_name(iso, year=False, full=False):
    """Aug, or Aug 2026; August 2026 in full."""
    d = AS_OF.replace(year=int(iso[:4]), month=int(iso[5:7]), day=1)
    return d.strftime(("%B" if full else "%b") + (" %Y" if year else ""))


def roster(repos):
    """The pro scene, repo by repo, with the build each one runs and the year of the first ROSS edition that named it (an edition's
    id ends on its year: q2-2020, annual-2023), names in alphabetical order."""
    names = {key: name for key, name, _, _ in BUILDS}
    return [
        {"name": r["name"], "first": int(r["ross"][0][-4:]), "build": names[build_of(r["now"])]}
        for r in sorted(repos, key=lambda r: r["name"].lower())
    ]


def median_lines(repos):
    """Median length of the main root instruction file, pointers left out."""
    sizes = []
    for r in repos:
        files = [
            i
            for i in r["scan"]["instructions"]
            if "/" not in i["path"]
            and i["rule"] in ("claude_md", "agents_md")
            and not i.get("pointer_only")
            and "symlink_to" not in i
        ]
        if files:
            sizes.append(max(i["lines"] for i in files))
    return int(statistics.median(sizes)) if sizes else 0


ROSS = read_json(
    DATA / "ross_index.json"
)  # the ROSS Index as data: its editions, its source and Runa Capital's own words


def long_day(iso):
    """2026-11-22 as 22 November 2026."""
    return dt.date.fromisoformat(iso).strftime("%-d %B %Y")


# the words of the pro scene's definition that name the rule both leagues share: the footer links them to it (copy.pro_rule)
PRO_RULE_WORDS = "the rule"


def copy(leagues, items, info, models, ctx, left_rows, jobs, dates, shown=None):
    """The sentences of the page that quote numbers. `items` holds every candidate counted, on the page or not, which a sentence
    may quote; `left_rows` the rows of What left on the page, which the notes rank. main() drops a note about
    a practice that is not on the page; the other sentences that name a practice say it only while it is on the page (`shown`, the
    ids of the practices on it; None: all), and are rebuilt without it, or empty, when it is not."""
    by = {i["id"]: i for i in items}
    on = lambda *keys: shown is None or set(keys) <= set(shown)
    clauses = lambda *parts: [text for text in parts if text]
    cap = lambda text: text[0].upper() + text[1:]
    cut = lambda lg, key, label: in_slice(ctx[lg], key, label)
    after_change = next(i for i, d in enumerate(dates) if d[:7] > "2026-09")
    job = lambda label: next((row["repos"]["k"] for row in jobs["rows"] if row["label"] == label), 0)
    bare = [
        (k, words)
        for k, words in (("hooks", "agent hooks"), ("mcp", "an MCP config"))
        if cut("pro", k, "Small")["k"] == 0
    ]
    pro, ladder = leagues["pro"], leagues["ladder"]
    rule, draw = info["rule"], info["ladder"]
    # how many repos the ladder stands for: the repos that pass the rule with MIN_STARS stars or more, estimated from the creation
    # days taken (drawn at random among every day of the span) as the pool per day taken times the days of the span, to two figures
    population = draw["pool"] / draw["days_taken"] * draw["span_days"]
    population = round(population, 2 - len(str(int(population))))
    owners = len({r["name"].split("/")[0] for r in pro})
    of = lambda x: "%d of %d" % (x["k"], x["n"])
    month_long = lambda iso: AS_OF.replace(year=int(iso[:4]), month=int(iso[5:7]), day=1).strftime("%B %Y")
    # the three practices removed most often: the first three of What left
    rows_by = {row["id"]: row for row in left_rows}
    out_most = [rows_by[key] for key in left_lists(left_rows)["left"][:3]]
    # and the first two of What stayed, the other end of the note: kept by the pro repos that had them a year ago. Not the rows taken
    # out least: that is What left read backwards, which puts on top what most repos added this year
    kept_most = [rows_by[key] for key in left_lists(left_rows)["stayed"][:2]]
    skills_pro = by["skills"]["pro"]
    no_skill = max(i for i, p in enumerate(skills_pro["series"]) if p == 0)
    # the ladder's repos with skills BACK snapshots ago: today's less those that added them, plus those that removed them
    skills_ladder = by["skills"]["ladder"]
    skills_then = skills_ladder["now"]["k"] - skills_ladder["moves"]["gained"] + skills_ladder["moves"]["lost"]
    _, several = stacked_review(pro)
    signed, opened, review = by["agent_commits"], by["agent_prs"], by["ai_review"]
    # Agents at work: a repo where agents sign commits, review pull requests or open them,
    # each by its practice's own threshold
    at_work = lambda repos: sum(1 for r in repos if any(r["now"][k] for k in AT_WORK))
    # the agent instruction file against the pull request template: the snapshot from which the file has been ahead in every one
    instr, template = by["instructions"], by["pr_template"]
    ahead = [a > b for a, b in zip(instr["pro"]["series"], template["pro"]["series"])]
    ahead_from = next(i for i in range(len(ahead) + 1) if all(ahead[i:]))  # len(ahead): behind today, or level
    # "up from 131", "down from 64", "unchanged"
    since_then = lambda now, then: (
        "up from %d" % then if now > then else "down from %d" % then if now < then else "unchanged"
    )
    # the pro repos that run their agent in CI, in the cloud or in parallel worktrees, and those with skills (the builds' intro)
    automated = [r for r in pro if any(r["now"][k] for k in AUTOMATION)]
    with_skills = [r for r in pro if r["now"]["skills"]]
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    # A note's chart holds the figures its sentence quotes, taken from the same values. Three forms: "trend" (lines over the
    # months, each a series of M.items named by item and league), "bars" (rows of shares, one column or a few) and "dots"
    # (one dot per repo, in parts that add up to n).
    share = lambda x: {"k": x["k"], "n": x["n"], "p": x["p"]}
    # skills in each main language of the pro scene the page shows, the lowest share first
    shown_langs = next(g["slices"] for g in ctx["pro"]["groups"] if g["name"] == "Main language")
    langs = sorted(
        ((sl["label"], cut("pro", "skills", sl["label"])) for sl in shown_langs), key=lambda x: (x[1]["p"], x[0])
    )
    return {
        # The short version: a headline, a sentence, the id of the section that holds the detail, the chart, and the
        # practices the note is about, which main() turns into its tags (note_tags). In the order the page shows them:
        # these, the note on What moved that main() writes, then those of Test, Secure and Ship (lens()).
        "notes": [
            # AI review, agents that sign commits and agents that open pull requests, in one note: each threshold said
            # with its figure
            [
                "Agents are at work in %d of the %d pro repos" % (at_work(pro), len(pro)),
                "%d pro repos have %d or more agent-signed commits in %d days, and %d an AI reviewer on pull requests (%d "
                "comments or more; %d run two reviewers or more). %d have %d or more agent-opened pull requests in their latest "
                "%d. On the ladder, %d of %d have one or more of the three."
                % (
                    signed["pro"]["now"]["k"],
                    MIN_SIGNED_COMMITS,
                    COMMIT_DAYS,
                    review["pro"]["now"]["k"],
                    MIN_REVIEW_COMMENTS,
                    several,
                    opened["pro"]["now"]["k"],
                    MIN_AGENT_PRS,
                    LATEST_ITEMS,
                    at_work(ladder),
                    len(ladder),
                ),
                "h-tools",
                {
                    "form": "bars",
                    "title": "Share of repos",
                    "value": "pct",
                    "cols": ["Pro scene", "Ladder"],
                    "groups": [
                        [
                            {
                                "label": label,
                                "cells": [dict(share(d[lg]["now"]), league=lg) for lg in ("pro", "ladder")],
                            }
                            for d, label in (
                                (signed, "Sign commits"),
                                (review, "Review pull requests"),
                                (opened, "Open pull requests"),
                            )
                        ]
                    ],
                },
                list(AT_WORK),
            ],
            [
                "Instructions are consolidating on AGENTS.md",
                # the moves that make it a consolidation: "14 removed CLAUDE.md, 13 added one" alone would read as a
                # wash (the run of 2026-11-22); the headline holds only while the moves say so
                "In %s %d pro repos added AGENTS.md and %s removed it, while CLAUDE.md went from %d to %d. AGENTS.md is in %s of the "
                "pro scene, CLAUDE.md in %s."
                % (
                    months(BACK),
                    by["agents_md"]["pro"]["moves"]["gained"],
                    by["agents_md"]["pro"]["moves"]["lost"] or "none",
                    by["claude_md"]["pro"]["now"]["k"]
                    - by["claude_md"]["pro"]["moves"]["gained"]
                    + by["claude_md"]["pro"]["moves"]["lost"],
                    by["claude_md"]["pro"]["now"]["k"],
                    pc(by["agents_md"]["pro"]["now"]),
                    pc(by["claude_md"]["pro"]["now"]),
                ),
                "h-moves",
                {
                    "form": "trend",
                    "title": "Share of the pro scene by month",
                    "lines": [
                        {"item": k, "league": "pro", "label": by[k]["label"]} for k in ("agents_md", "claude_md")
                    ],
                },
                ["claude_md", "agents_md"],
            ],
            # written only while the instruction file is ahead today; the month from which it has been ahead at every snapshot
            *(
                [
                    [
                        "More pro repos now have an agent instruction file than a pull request template",
                        "%d of %d have an instruction file, up from %d in %s; %d have a pull request template, %s. The instruction "
                        "file has been ahead since %s. On the ladder, %d repos have an instruction file and %d a template."
                        % (
                            instr["pro"]["now"]["k"],
                            instr["pro"]["now"]["n"],
                            instr["pro"]["first"]["k"],
                            month_long(dates[0]),
                            template["pro"]["now"]["k"],
                            since_then(template["pro"]["now"]["k"], template["pro"]["first"]["k"]),
                            month_long(dates[ahead_from]),
                            instr["ladder"]["now"]["k"],
                            template["ladder"]["now"]["k"],
                        ),
                        "h-build",
                        {
                            "form": "trend",
                            "title": "Share of the pro scene by month",
                            "mark": ahead_from,
                            "lines": [
                                {"item": k, "league": "pro", "label": by[k]["label"]}
                                for k in ("instructions", "pr_template")
                            ],
                        },
                        ["instructions", "pr_template"],
                    ]
                ]
                if ahead_from < len(ahead)
                else []
            ),
            # the ladder's move since BACK snapshots, "doubled" only while it did
            [
                "Skills went from zero to %s of the pro scene in %d months"
                % (pc(skills_pro["now"]), len(dates) - 1 - no_skill),
                "No pro repo had a skill as late as %s. Today %s do. On the ladder, repos with skills %s in %s, from %d to %d of %d."
                % (
                    month_long(dates[no_skill]),
                    of(skills_pro["now"]),
                    "doubled" if 0 < 2 * skills_then <= skills_ladder["now"]["k"] else "went",
                    months(BACK),
                    skills_then,
                    skills_ladder["now"]["k"],
                    skills_ladder["now"]["n"],
                ),
                "h-build",
                {
                    "form": "trend",
                    "title": "Skills, share of repos by month",
                    "mark": no_skill,
                    "lines": [
                        {"item": "skills", "league": lg, "label": label}
                        for lg, label in (("pro", "Pro scene"), ("ladder", "Ladder"))
                    ],
                },
                ["skills"],
            ],
            # browser end-to-end tests beside skills, while they are on the page: size separates a practice not
            # specific to AI as much (a row of CONTEXT_NOTES, which By context's table does not show)
            [
                "Repo size is what separates setups",
                "Skills are in %s of the largest third of pro repos and %s of the smallest%s. AI review does not move with size."
                % (
                    pc(cut("pro", "skills", "Large")),
                    pc(cut("pro", "skills", "Small")),
                    ", browser end-to-end tests in %s and %s"
                    % (pc(cut("pro", "e2e_browser", "Large")), pc(cut("pro", "e2e_browser", "Small")))
                    if on("e2e_browser")
                    else "",
                ),
                "h-ctx",
                {
                    "form": "bars",
                    "title": "Share of pro repos, by size third",
                    "value": "pct",
                    "cols": ["Small", "Mid", "Large"],
                    "groups": [
                        [
                            {
                                "label": label,
                                "id": key,
                                "cells": [
                                    dict(share(cut("pro", key, third)), league="pro")
                                    for third in ("Small", "Mid", "Large")
                                ],
                            }
                            for key, label in (
                                ("skills", "Skills"),
                                ("e2e_browser", LENS_CHART_NAME["e2e_browser"]),
                                ("ai_review", "AI review"),
                            )
                            if key != "e2e_browser" or on("e2e_browser")
                        ]
                    ],
                },
                ["skills", "ai_review"] + (["e2e_browser"] if on("e2e_browser") else []),
            ],
            [
                "Taken out most often: %s" % ", ".join(row["label"] for row in out_most),
                "Pro repos that removed it, of those that had it: %s. "
                "At the other end, pro repos that had it a year ago and still have it: %s."
                % (
                    ", ".join("%s %s" % (row["label"], of(row["left"])) for row in out_most),
                    ", ".join("%s %s" % (row["label"], of(row["stayed"])) for row in kept_most),
                ),
                "h-left",
                {
                    "form": "bars",
                    "title": "Pro repos that removed it, of those that had it",
                    "value": "of",
                    # the three taken out most often alone: the other end is another measure, What stayed's, over another base
                    "groups": [
                        [
                            {
                                "label": LENS_CHART_NAME.get(row["id"], row["label"]),
                                "id": row["id"],
                                "cells": [dict(share(row["left"]), league="pro")],
                            }
                            for row in out_most
                        ]
                    ],
                },
                [row["id"] for row in out_most + kept_most],
            ],
        ],
        "pro": "%d public repos from %d organisations: every repo the ROSS Index has named since %s that passes %s both "
        "leagues share." % (len(pro), owners, ROSS["editions"][0]["id"][-4:], PRO_RULE_WORDS),
        # the words of "pro" that the footer links to the rule on the Method tab; the page links them only where it
        # finds them
        "pro_rule": PRO_RULE_WORDS,
        "ladder": "%d repos drawn at random from the roughly %s organisations' repos that pass the same rule and have %d stars or "
        "more, the pro scene left out." % (len(ladder), "{:,}".format(int(population)), rule["min_stars"]),
        # said of the pro scene, where it holds: on the ladder, repos with skills do not all have an instruction file
        # the line under Build's part "Setups"
        "builds": " ".join(
            clauses(
                "Setups stack as layers, not rival schools: in the pro scene, %s repos that automate their agent write skills, "
                "and %s with skills have an instruction file."
                % (
                    of_the(sum(1 for r in automated if r["now"]["skills"]), len(automated)),
                    of_the(sum(1 for r in with_skills if r["now"]["instructions"]), len(with_skills)),
                )
                if on("skills", "instructions")
                else "",
                "Each repo counts in the heaviest setup it qualifies for, the heaviest first.",
            )
        ),
        # the release, then what followed it: the CLAUDE.md removals, the .agents/ directories; the release alone says nothing here
        "moves": (
            lambda after: (
                "In September 2026 Claude Code began reading AGENTS.md when a folder has no CLAUDE.md. %s."
                % cap(", and ".join(after))
                if after
                else ""
            )
        )(
            clauses(
                "%d of the %d CLAUDE.md removals came by the next snapshot"
                % (removed_by(pro, "claude_md", after_change), by["claude_md"]["pro"]["moves"]["lost"])
                if on("claude_md")
                else "",
                "%d pro repos adopted a shared .agents/ directory" % by["agents_dir"]["pro"]["moves"]["gained"]
                if on("agents_dir")
                else "",
            )
        ),
        # the studies of a practice card are the outside evidence of the section its practice is in, AI review's in Test
        "stamp": "Every figure on this page is observed, counted in public repos: what teams do and keep, not proof that it works. "
        "Where a controlled test is published, the outside evidence of the practice's section cites it.",
        "left": " ".join(
            clauses(
                "llms.txt is left out: it usually moves into the docs build, which reads as a removal (%d of %d still have one)."
                % (by["ai_docs"]["pro"]["kept"]["k"], by["ai_docs"]["pro"]["kept"]["n"])
                if on("ai_docs")
                else "",
                "Agent-signed commits count as gone below %d in %d days: less work, or a signature switched off."
                % (MIN_SIGNED_COMMITS, COMMIT_DAYS)
                if on("agent_commits")
                else "",
                "A file moved where no rule looks counts as gone.",
            )
        ),
        # not "language changes little": on the run of 2026-11-22, skills were in a third of the pro scene's Python
        # repos and over half of its TypeScript or JS ones
        "context": " ".join(
            clauses(
                "%s of the largest third ship skills, %s of the smallest%s."
                % (
                    pc(cut("pro", "skills", "Large")),
                    pc(cut("pro", "skills", "Small")),
                    "; no repo in the smallest third has %s" % " or ".join(words for k, words in bare if on(k))
                    if any(on(k) for k, _ in bare)
                    else "",
                )
                if on("skills")
                else "",
                "AI review does not move with size (%s, %s, %s)."
                % tuple(pc(cut("pro", "ai_review", label)) for label in ("Small", "Mid", "Large"))
                if on("ai_review")
                else "",
                "By main language, skills are in %d of %d %s repos and %d of %d %s ones."
                % (langs[0][1]["k"], langs[0][1]["n"], langs[0][0], langs[-1][1]["k"], langs[-1][1]["n"], langs[-1][0])
                if on("skills")
                else "",
            )
        ),
        "regimes": [
            # "we compute": Build's outside evidence also quotes studies' figures, two of them Benchmarked
            [
                "Data-driven",
                "On this page",
                "Engineering leaves public traces: files, commits, pull requests. Every figure we compute counts them, labelled Observed.",
            ],
            [
                "Community-driven",
                "Interviews not started",
                "Design, product and what happens inside a session leave no public trace: they will come from practitioners, labelled Reported, with no pick rate."
                + (
                    " Of the %d pro repos with skills, %d have one for design or UX, %d for planning, specs or issues."
                    % (jobs["repos"], job("Design and UX"), job("Planning, specs and issues"))
                    if on("skills")
                    else ""
                ),
            ],
        ],
        # both counts are over the months of models["months"], from the first (model_history)
        # not "older ones": the commits that only say Claude are spread over the same months as the named ones
        "heat": "%s Claude-signed commits since %s name their model; %s others only say Claude and are left out. "
        "Other agents name no model."
        % (
            "{:,}".format(models["named"]),
            month_name(models["months"][0], year=True, full=True),
            "{:,}".format(models["unnamed"]),
        ),
        # no dates: the page is dated by its issue
        "foot": "The Tech Meta, v1. Built from public git history and the GitHub API. "
        "No person in the data is named or counted: only repos, files and bot accounts.",
    }


# ---------- The lenses: Test, Secure and Ship (checks, security, ship) ------------------------------
# The same repos, read a second way. A lens practice is a practice like the others (a yes/no question asked of a repo at
# a date) that also belongs to a lens. The page gives each lens a section of its own, so that its practices are not lost
# among the agent practices. Tests, linters and security policies are older than agents and near-universal among the
# pros, so the lenses look at what changed since the first snapshot. An old habit is in the meta like any other
# practice, of kind "any": what is counted is what strong teams do, however old the practice.
# The share of a repo's steps that must comply for it to have a practice counted as a share: of its third-party actions,
# those pinned to a full commit SHA; of its YAML workflows, those that scope their token; of its actions/checkout steps,
# those that set persist-credentials: false. Pinned actions: repos are at one end or the other (23 pro under 10%, 62 at
# 90% or more, 11 between, on 2026-11-21): the threshold sits in the gap. An action of the repo's own account is not a
# third party's. The two token practices take the same share, not every workflow and every step: one workflow added
# without the setting would read as a removal.
COMPLIANT_SHARE = 0.9
MIN_CODE_FILES = 50  # code files at both dates for a repo's share of test files to be compared
# The scanners that audit the dependencies, less the two that count a check of something else: cargo_audit takes `cargo deny check
# licenses`, pip_audit a "safety check" written in a message. The scan's supply "audit" reads Rust and Python again, on advisories
# and on a command (fingerprints.CI_SUPPLY), and adds Ruby, PHP, Elixir, .NET and container images.
DEP_AUDIT = set(fp.SCANNER_JOBS["deps"]) - {"cargo_audit", "pip_audit"}

# The sections of the Practices tab after Build, in their order (Build, Test, Secure, Ship): the field's id, the
# section's name, and the line under it that says what it covers.
LENSES = [
    ("checks", "Test", "How a change is checked before it lands: by machines, by reviewers, by agents."),
    ("security", "Secure", "How the repo and what it ships are protected from mistakes and attacks."),
    ("ship", "Ship", "How a change reaches its users: releases, packages, images, deploys."),
]
# The practices read from the lens read of a snapshot (its `checks` and `sec`, lens_features()), over the repos read for
# it, and the settings and bots of GitHub's API: id, label, history (False = from the GitHub API, today only), what we
# look for. Their field, kind and on are in PRACTICES. The kind: "agent" exists because of coding agents, "any" serves
# any team, older than agents or not.
LENS_ITEMS = [
    (
        "says_tests",
        "Test command in the instructions",
        True,
        "a root instruction file that names a command to run the tests",
    ),
    (
        "checks_ext",
        "Skills and commands for tests",
        True,
        "a skill, command or subagent named for tests, lint, types or CI",
    ),
    (
        "hook_checks",
        "Checks run by agent hooks",
        True,
        "an agent hook that runs a formatter, a linter, a type check or tests after an edit or at the end of a turn",
    ),
    (
        "fast_lint",
        "Oxlint, Oxfmt or Biome",
        True,
        "a config file of one of the three, or the tool in the root package.json",
    ),
    (
        "custom_lint",
        "Lint rules of their own",
        True,
        "rule files in a local plugin or a rules folder: ESLint, Oxlint, Biome or Grit, ast-grep, Semgrep, ruleguard. "
        "A plugin released as a package is left out",
    ),
    (
        "knip",
        "Unused-code check (Knip)",
        True,
        "a Knip config, or knip in the root package.json",
    ),
    (
        "git_hooks",
        "Git hooks",
        True,
        "husky, lefthook, simple-git-hooks, pre-commit or a folder of hook scripts",
    ),
    (
        "ci_tests",
        "Tests in CI",
        True,
        "a test command run by a GitHub Actions workflow",
    ),
    (
        "ci_lint",
        "Lint in CI",
        True,
        "a linter or a formatter run by a GitHub Actions workflow",
    ),
    (
        "ci_types",
        "Type check in CI",
        True,
        "a type checker run by a GitHub Actions workflow (tsc, mypy, pyright and the like; a compiler's own check "
        "is not one)",
    ),
    (
        "kept_from_agent",
        "Files kept from the agent",
        True,
        ".cursorignore, .aiexclude, .claudeignore and the like, or a deny rule on secrets in committed settings",
    ),
    (
        "says_security",
        "Security rules in the instructions",
        True,
        "a root instruction file with a heading about security, or a rule against committing or logging secrets",
    ),
    (
        "perm_rules",
        "Permission rules committed",
        True,
        "an allow, ask or deny list in .claude/settings.json, or .cursor/cli.json, .codex/rules, .gemini/policies",
    ),
    (
        "guard_hook",
        "Hook that can block an action",
        True,
        "an agent hook on an event that fires before a tool call or a prompt",
    ),
    (
        "security_ext",
        "Skills and commands for security",
        True,
        "a skill, command or subagent named for security, vulnerabilities or threats",
    ),
    (
        "fence_tools",
        "Agent's tools limited in CI",
        True,
        "a workflow that calls a coding agent and lists the tools it may or may not use, without allowing every shell command",
    ),
    (
        "pinned",
        "Actions pinned to a commit",
        True,
        "%s or more of the third-party actions in the workflows pinned to a full commit SHA" % percent(COMPLIANT_SHARE),
    ),
    (
        "zizmor",
        "Workflow audit (zizmor)",
        True,
        "a zizmor config, or zizmor called from a workflow",
    ),
    # security as a whole: what the workflows do to the supply chain
    (
        "token_scoped",
        "Workflow tokens scoped",
        True,
        "a permissions key, other than write-all, at the top of %s or more of a repo's YAML workflows, or in each of their jobs; "
        "a repo with no workflow does not have it" % percent(COMPLIANT_SHARE),
    ),
    (
        "checkout_no_token",
        "Checkout keeps no token",
        True,
        "persist-credentials: false on %s or more of the actions/checkout steps of a repo's workflows; a repo with no "
        "checkout step does not have it" % percent(COMPLIANT_SHARE),
    ),
    (
        "signed_builds",
        "Signed or attested builds",
        True,
        "a workflow that signs or attests what it builds: GitHub's attest actions, SLSA's generator, cosign sign or attest, "
        "npm's --provenance, a provenance or attestations input set to true",
    ),
    (
        "sbom",
        "SBOM",
        True,
        "a workflow that writes a software bill of materials: syft, CycloneDX, an SPDX file, buildx's --sbom, an sbom input "
        "set to true",
    ),
    (
        "threat_model",
        "Threat model committed",
        True,
        "a markdown file named for a threat model",
    ),
    (
        "cooldown",
        "Release cooldown",
        True,
        "a minimum release age in the pnpm, npm, Yarn, Bun or uv config, or a cooldown in Dependabot or Renovate",
    ),
    (
        "code_scan",
        "Code scanning in CI",
        True,
        "CodeQL, Semgrep, Sonar, Snyk Code, Bandit or gosec run by a workflow",
    ),
    ("dep_bot", "Dependency bot", True, "a Dependabot or Renovate config"),
    (
        "security_md",
        "Security policy",
        True,
        "SECURITY.md at the root, in .github/ or in docs/",
    ),
    (
        "codeowners",
        "Code owners",
        True,
        "a CODEOWNERS file at the root, in .github/ or in docs/, where GitHub reads it",
    ),
    (
        "dep_audit_ci",
        "Dependency audit in CI",
        True,
        "a workflow that checks the dependencies for known vulnerabilities: an npm, pnpm or yarn audit, dependency review, "
        "OSV-Scanner, Trivy, Grype, Snyk, Socket, govulncheck, cargo audit, cargo deny on advisories, pip-audit and the like",
    ),
    (
        "fuzz_tests",
        "Fuzz tests",
        True,
        "code in a fuzz folder, a fuzz target named so or a ClusterFuzzLite setup, or a fuzzer run by a workflow",
    ),
    (
        "secret_scan_ci",
        "Secret scanning in CI or config",
        True,
        "Gitleaks, TruffleHog, GitGuardian, detect-secrets or secretlint run by a workflow, a config file of one of them, "
        "or a git hook that scans for secrets",
    ),
    # three settings GitHub's API shows anyone for a public repo (api_signals.security, security_settings): today only, as the
    # security bots
    (
        "branch_protected",
        "Default branch protected",
        False,
        "the default branch reported as protected by GitHub's API: a branch protection rule or a ruleset",
    ),
    (
        "pr_required",
        "Pull request required",
        False,
        "a rule that requires a pull request among those GitHub's API lists for the default branch, the rules of its rulesets",
    ),
    (
        "private_reporting",
        "Private vulnerability reporting on",
        False,
        "private vulnerability reporting turned on, as GitHub's API reports it",
    ),
    (
        "sec_bots",
        "Security bot on pull requests",
        False,
        "%d or more recent comments from a security bot: code scanning, dependency or secret alerts, security review"
        % MIN_BOT_COMMENTS,
    ),
]
# Dated outside events, drawn as ticks on the lens charts: month, lens, label, the page that dates it.
# The span of the report note on pinned actions, in snapshots: the JUMP in which the most pro repos pinned them
JUMP = 2
LENS_EVENTS = [
    ("2025-06", "checks", "Oxlint 1.0", "https://oxc.rs/blog/2025-06-10-oxlint-stable.html"),
    ("2025-12", "checks", "Oxfmt alpha", "https://oxc.rs/blog/2025-12-01-oxfmt-alpha.html"),
    ("2026-03", "checks", "Oxlint runs ESLint plugins", "https://oxc.rs/blog/2026-03-11-oxlint-js-plugins-alpha.html"),
    (
        "2025-03",
        "security",
        "tj-actions/changed-files compromised",
        "https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066",
    ),
    (
        "2025-09",
        "security",
        "Shai-Hulud npm worm",
        "https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem",
    ),
    (
        "2026-03",
        "security",
        "trivy-action tags hijacked",
        "https://www.cisa.gov/news-events/alerts/2026/03/26/cisa-adds-one-known-exploited-vulnerability-catalog",
    ),
    ("2026-04", "security", "pnpm 11 waits a day by default", "https://pnpm.io/blog/releases/11.0"),
    (
        "2026-05",
        "security",
        "TanStack packages compromised",
        "https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",
    ),
    (
        "2026-07",
        "security",
        "Dependabot waits three days by default",
        "https://github.blog/changelog/2026-07-14-dependabot-version-updates-introduce-default-package-cooldown/",
    ),
]
# What a practice is read in, "repo files" when it is not here; fuzz tests and secret scanning are read in the tree and in the
# workflows, which are repo files too. The words stand on one line in Every number: past the 17 characters of "instruction files"
# they push the table out of its card on a screen 1280px wide.
LENS_SEEN = {
    "ci_tests": "workflow files",
    "ci_lint": "workflow files",
    "ci_types": "workflow files",
    "fence_tools": "workflow files",
    "pinned": "workflow files",
    "code_scan": "workflow files",
    "sec_bots": "pull requests",
    "says_tests": "instruction files",
    "says_security": "instruction files",
    "hook_checks": "agent settings",
    "guard_hook": "agent settings",
    "token_scoped": "workflow files",
    "checkout_no_token": "workflow files",
    "signed_builds": "workflow files",
    "sbom": "workflow files",
    "dep_audit_ci": "workflow files",
    "branch_protected": "GitHub's API",
    "pr_required": "GitHub's API",
    "private_reporting": "GitHub's API",
}
LENS_ABOUT = {
    "says_tests": "The instruction file tells the agent which command runs the tests, so it can check its own work.",
    "checks_ext": "A skill, a saved prompt or a helper agent whose job is to write, run or fix tests, lint or CI.",
    "hook_checks": "A hook that runs the formatter, the linter, the type check or the tests when the agent edits a file.",
    "fast_lint": "Linters and formatters written in Rust: the newer alternatives to ESLint and Prettier.",
    "custom_lint": "Lint rules the team wrote for its own code: a convention turned into an error a machine reports.",
    "knip": "A tool that finds files, exports and dependencies nothing uses any more, so dead code gets removed.",
    "git_hooks": "Scripts git runs before a commit or a push, such as a linter on the changed files.",
    "ci_tests": "The test suite runs in GitHub Actions, where a change is checked before it is merged.",
    "ci_lint": "A linter or a formatter runs in GitHub Actions.",
    "ci_types": "A type checker runs in GitHub Actions.",
    "kept_from_agent": "A list of files the agent must not read: an ignore file, or a deny rule on secrets in its settings.",
    "says_security": "The instruction file has a section on security, or tells the agent never to commit or log a secret.",
    "perm_rules": "A list shared by the team of what the agent may do without asking, and what it may never do.",
    "guard_hook": "A script that runs before the agent acts and can refuse: a risky command, an edit to a protected file.",
    "security_ext": "A skill, a saved prompt or a helper agent whose job is a security review, an audit or a fix.",
    "fence_tools": "The workflow that runs the agent names the tools it may use, and does not hand it the whole shell.",
    "pinned": "Each GitHub Action is called by a commit hash, not by a tag its author can move to new code.",
    "zizmor": "A linter for GitHub Actions workflows: injection risks, loose permissions, actions that are not pinned.",
    "threat_model": "A written analysis of what could go wrong and who could attack, kept in the repo for people and agents.",
    "cooldown": "A wait of some days before a newly published package version can be installed.",
    "code_scan": "A static analysis tool, run from a workflow, looks for vulnerabilities in the code.",
    "dep_bot": "A bot that opens pull requests to update dependencies.",
    "security_md": "SECURITY.md: how to report a vulnerability in the project.",
    "token_scoped": "A repo's workflows say what their GitHub token may do, instead of taking the default rights.",
    "checkout_no_token": "The checkout steps leave the GitHub token off the disk, where a later step could read it.",
    "signed_builds": "A workflow signs what it builds, or attests where it was built, so a user can check where it came from.",
    "sbom": "A workflow writes a software bill of materials: the list of the components inside what it ships.",
    "codeowners": "A file that names who owns each part of the code; GitHub asks them to review a change to it.",
    "dep_audit_ci": "A workflow checks the dependencies against lists of known vulnerabilities.",
    "fuzz_tests": "Tests that feed the code random or malformed input, to find the crashes ordinary tests miss.",
    "secret_scan_ci": "A scanner looks for keys and passwords committed by mistake: in CI, in a git hook, or set up by a config.",
    "branch_protected": "GitHub protects the default branch: a rule limits who can push to it, or how.",
    "pr_required": "A rule of the default branch lets a change in only through a pull request.",
    "private_reporting": "Anyone can tell the maintainers of a vulnerability in private, on GitHub, before it is made public.",
    "sec_bots": "A bot that comments on pull requests with security findings: code, dependencies or secrets.",
}
# Security bots on pull requests: a prefix of the lowercased login, and the name shown. Company-built
# ones are accepted on the word "security" in their name and shown under one label.
SECURITY_BOTS = [
    ("github-advanced-security", "GitHub code scanning"),
    ("socket-security", "Socket"),
    ("gitguardian", "GitGuardian"),
    ("corridor-security", "Corridor"),
    ("aikido", "Aikido"),
    ("hacktron", "Hacktron"),
    ("strix-security", "Strix"),
    ("superagent-security", "Superagent"),
    ("snyk", "Snyk"),
    ("sonarqubecloud", "SonarQube Cloud"),
    ("semgrep", "Semgrep"),
    ("gecko-security", "Gecko"),
]
OWN_SECURITY_BOT = "Built in-house"
# What each scanner called from CI is shown as.
SCANNER_NAMES = {
    "codeql": "CodeQL",
    "semgrep": "Semgrep",
    "sonar": "Sonar",
    "snyk": "Snyk",
    "code_lint": "Bandit, gosec or Brakeman",
    "trivy": "Trivy",
    "grype": "Grype",
    "osv": "OSV-Scanner",
    "govulncheck": "govulncheck",
    "cargo_audit": "cargo audit or deny",
    "pip_audit": "pip-audit or Safety",
    "npm_audit": "npm, pnpm or yarn audit",
    "dependency_review": "Dependency review",
    "socket": "Socket",
    "gitleaks": "Gitleaks",
    "trufflehog": "TruffleHog",
    "gitguardian": "GitGuardian",
    "scorecard": "OpenSSF Scorecard",
    "zizmor": "zizmor",
    "actionlint": "actionlint",
    "harden_runner": "Harden-Runner",
}
COOLDOWN_NAMES = {
    "pnpm": "pnpm",
    "npm": "npm",
    "yarn": "Yarn",
    "bun": "Bun",
    "uv": "uv",
    "dependabot": "Dependabot",
    "renovate": "Renovate",
}
# For the repos that took a tool out: what they may run today, and how to say it.
LENS_LEFT = [
    ("eslint", "ESLint", "The JavaScript linter most repos started from, with its rules in a config file."),
    ("prettier", "Prettier", "The JavaScript formatter most repos started from."),
]
# Beyond its own section, a lens practice is on the map, in What moved and in What left like any other practice,
# with one exception.
# What an instruction file says is read from its text: a file rewritten shorter, or turned into a link to another
# folder, reads as a removal, so it is on the map and counted in neither What moved nor What left (as llms.txt is
# kept out of What left).
LENS_TEXT_READ = {"says_tests", "says_security"}
# For the repos that removed a lens practice: something true of them today, and how to say it.
LENS_LEFT_FOR = {
    "fence_tools": (lambda f: not f["agent_in_ci"], "no longer run an agent in CI"),
    "perm_rules": (lambda f: not f["perms"], "no longer commit a .claude/settings.json"),
}
# In a report note's chart a name stands beside its bar or at the end of its line, on a phone 320px wide too: 22 characters
# at most. A practice whose name is longer goes by a shorter one there, and only there: a chart's row then carries the
# practice's id, so that it can still be matched to the practice.
LENS_CHART_NAME = {
    "pinned": "Pinned actions",
    "fence_tools": "Tools limited in CI",
    "checkout_no_token": "No token on checkout",
    "signed_builds": "Signed builds",
    # the practices read as unions of traces (TRACES) that have a history and a longer name, ready for when one ranks
    # there
    "dev_env_declared": "Dev env as code",
    "ci_concurrency": "Stale runs cancelled",
    "e2e_browser": "Browser e2e tests",
    "ci_path_filters": "CI by changed files",
    "ci_services": "Services in CI",
    "container_images": "Images published by CI",
    "multi_arch_images": "Multi-arch images",
    "environments": "CI environments",
    "publish_package": "Packages published",
    "change_convention": "Commit convention",
}


def security_settings(api):
    """The three security settings of the lens read from GitHub's API (api_signals.security), today only. A call that
    failed leaves its field null, which is not the setting: it counts as without it, and an API file read before
    2026-11-22 has no field at all."""
    sec = api.get("security") or {}
    return {
        "branch_protected": sec.get("protected") is True,
        "pr_required": "pull_request" in (sec.get("branch_rules") or []),
        "private_reporting": sec.get("private_reporting") is True,
    }


def security_bots(api):
    """Security bots with MIN_BOT_COMMENTS or more recent comments on pull requests, by the name shown."""
    found = collections.Counter()
    for source in ("review_bots", "pr_comment_bots"):
        for login, n in api[source].items():
            name = login.lower().replace("[bot]", "")
            label = next((label for prefix, label in SECURITY_BOTS if name.startswith(prefix)), None)
            if label is None and "secur" in name:
                label = OWN_SECURITY_BOT
            if label:
                found[label] += n
    return sorted(label for label, n in found.items() if n >= MIN_BOT_COMMENTS)


# The sandbox modes of a Codex config that restrict the agent (sandbox_mode in .codex/config.toml, read lowercased by the scan).
# danger-full-access turns the sandbox off, so it does not count as a sandbox.
CODEX_SANDBOXES = ("read-only", "workspace-write")


def lens_features(scan, i):
    """Answers of one repo at snapshot i for the lens practices, or None when that snapshot was not read for them."""
    s = scan["snaps"][i]
    if s is None or "checks" not in s:
        return None
    hits = scan["sets"][s["set"]]["hits"]
    n = lambda rule: count(rule, hits.get(rule))
    checks, sec = s["checks"], s["sec"]
    tools, says, scanners = set(checks["tools"]), set(checks["says"]), set(sec["scanners"])
    hooks, perms, agent = (
        checks["hooks"] or {"checks": [], "guard": 0},
        sec["perms"] or {},
        sec["agent"] or {"fence": []},
    )
    pinned, floating = sec["pins"][2], sec["pins"][3]
    has = lambda *names: any(n(x) > 0 or x in tools for x in names)
    # the supply fields, which a snapshot scanned before 2026-11-22 lacks: it then has none of these practices
    supply = set(sec.get("supply") or [])
    mostly = lambda pair: (
        bool(pair) and pair[0] > 0 and pair[1] >= COMPLIANT_SHARE * pair[0]
    )  # [steps, those that comply]: the share, and one step at least
    f: dict = {
        # checks
        "says_tests": "tests" in says,
        "checks_ext": n("checks_ext") > 0,
        "hook_checks": bool(hooks["checks"]),
        "fast_lint": has("oxlint", "oxfmt", "biome"),
        "custom_lint": n("custom_lint") > 0,
        "knip": has("knip"),
        "git_hooks": n("git_hooks") > 0 or bool(tools & {"husky", "lefthook", "simple_git_hooks"}),
        "ci_tests": "tests" in checks["ci"],
        "ci_lint": "lint" in checks["ci"],
        "ci_types": "types" in checks["ci"],
        # security
        "kept_from_agent": n("agent_ignore") > 0 or bool(perms.get("secrets")),
        "says_security": bool({"security", "secrets"} & says),
        "perm_rules": bool(perms.get("allow") or perms.get("deny") or perms.get("ask")) or n("agent_permissions") > 0,
        "guard_hook": hooks["guard"] > 0,
        "security_ext": n("security_ext") > 0,
        "fence_tools": "tools" in agent["fence"] and "bash" not in agent["fence"],
        "pinned": pinned + floating > 0 and pinned >= COMPLIANT_SHARE * (pinned + floating),
        "zizmor": n("zizmor") > 0 or "zizmor" in scanners,
        # the share of the workflows, of the checkout steps (COMPLIANT_SHARE)
        "token_scoped": mostly(sec.get("token")),
        "checkout_no_token": mostly(sec.get("checkout")),
        "signed_builds": "provenance" in supply,
        "sbom": "sbom" in supply,
        "threat_model": n("threat_model") > 0,
        "cooldown": bool(sec["cooldown"]),
        "code_scan": bool(scanners & set(fp.SCANNER_JOBS["code"])),
        "dep_bot": n("dependabot") > 0 or n("renovate") > 0,
        "security_md": n("security_md") > 0,
        "codeowners": n("codeowners") > 0,
        "dep_audit_ci": bool(scanners & DEP_AUDIT) or "audit" in supply,
        "fuzz_tests": n("fuzz_tests") > 0 or "fuzz" in supply,
        "secret_scan_ci": (
            bool(scanners & set(fp.SCANNER_JOBS["secrets"]))
            or "secrets" in supply
            or n("secret_scan") > 0
            or "secrets" in checks["git"]
        ),
    }
    # what the lists and the readings count, beside the practices
    f.update(
        {
            "instructions_root": any((hits.get(r) or {}).get("root", 0) for r in fp.INSTRUCTION_RULES),
            "says": says,
            "hook_runs": set(hooks["checks"]),
            "git_runs": set(checks["git"]),
            "agent_in_ci": bool(sec["agent"]),
            "fence": set(agent["fence"]),
            "perms": perms,
            "sandbox": bool(perms.get("sandbox")) or bool(sec["codex"] and sec["codex"]["sandbox"] in CODEX_SANDBOXES),
            "cooldown_in": set(sec["cooldown"]),
            "scanners": scanners,
            "code": checks["code"],
            "eslint": has("eslint"),
            "prettier": has("prettier"),
            "tool": {k: has(k) for k in ("oxlint", "oxfmt", "biome", "eslint", "prettier", "knip")},
            "pkg": tools,
            # the package manager waits before a new release without being told to: pnpm 11, Yarn 4.15
            "waits_by_default": bool(sec.get("manager"))
            and (
                (sec["manager"][0] == "pnpm" and sec["manager"][1] >= 11)
                or (sec["manager"][0] == "yarn" and tuple(sec["manager"][1:]) >= (4, 15))
            ),
        }
    )
    return f


def lens_view(repos):
    """The repos whose snapshots were read for the lenses, with the lens answers in the place of the practices'.

    series(), moves(), retention() and departures() then count a lens practice as they count any other.
    """
    return [
        dict(r, f=r["g"], now={**r["g"][-1], "sec_bots": bool(r["api"]["security_bots"]), **r["api"]["settings"]})
        for r in repos
        if r["g"][-1] is not None
    ]


def lens_lists(views):
    """The ranked lists under each lens: what a practice is made of today. A list counts over a base it names.

    Each row is (label, a test of today's answers). Every list is sorted by its pro count, highest first, then by its ladder
    count, then in the order written, so that the order is one the reader can see. A ranked list
    keeps its best eight and drops what no pro repo has; the others drop what no repo of either league has.
    """
    is_in = lambda key, value: lambda f: value in f[key]
    everyone = lambda f: True
    lists = [
        (
            "checks",
            "says",
            "What the instruction file names",
            "Of the repos with an instruction file at the root. Read from its text.",
            lambda f: f["instructions_root"],
            False,
            [
                ("A command to run the tests", is_in("says", "tests")),
                ("A lint or format command", is_in("says", "lint")),
                ("A type check", is_in("says", "types")),
                ("All three", lambda f: {"tests", "lint", "types"} <= f["says"]),
            ],
        ),
        (
            "checks",
            "hook_runs",
            "What agent hooks run",
            # over all repos: over the repos with a check in an agent hook, under the floor in both leagues, the card
            # would show counts and no bar
            "Of all repos: those with an agent hook are too few to count over. "
            "A check the hook runs after an edit or at the end of a turn.",
            everyone,
            True,
            [
                ("A formatter", is_in("hook_runs", "format")),
                ("A linter", is_in("hook_runs", "lint")),
                ("A type check", is_in("hook_runs", "types")),
                ("Tests", is_in("hook_runs", "tests")),
                ("Another check script", is_in("hook_runs", "check")),
            ],
        ),
        (
            "checks",
            "git_runs",
            "What git hooks run",
            "Of the repos with git hooks. Read from the hook scripts and configs.",
            lambda f: f["git_hooks"],
            True,
            [
                ("A linter or a formatter", is_in("git_runs", "lint")),
                ("A type check", is_in("git_runs", "types")),
                ("Tests", is_in("git_runs", "tests")),
                ("A secret scan", is_in("git_runs", "secrets")),
            ],
        ),
        (
            "security",
            "cooldown_in",
            "Where the cooldown is set",
            "Of the repos with a release cooldown. A repo can set it in several places, "
            "and in a package of a monorepo.",
            lambda f: f["cooldown"],
            True,
            [(COOLDOWN_NAMES[k], is_in("cooldown_in", k)) for k in COOLDOWN_NAMES],
        ),
        (
            "security",
            "fence",
            "How the agent runs in CI",
            "Of the repos whose workflows call a coding agent. Read from the workflow text, "
            "over all of a repo's agent workflows.",
            lambda f: f["agent_in_ci"],
            False,
            [
                ("Its tools are listed", is_in("fence", "tools")),
                # "Its tool list", not "It": sorted by count, this row need not sit under "Its tools are listed"
                ("Its tool list allows every shell command", is_in("fence", "bash")),
                ("Only members can trigger it", is_in("fence", "assoc")),
                ("Named bots can trigger it", is_in("fence", "bots")),
                ("Anyone can trigger it", is_in("fence", "open")),
                ("Its sandbox or its approvals are switched off", is_in("fence", "skip")),
                ("Triggered by pull_request_target", is_in("fence", "target")),
            ],
        ),
        (
            "security",
            "perms",
            "What committed permissions hold",
            "Of the repos with a committed .claude/settings.json.",
            lambda f: bool(f["perms"]),
            False,
            [
                ("An allow list", lambda f: f["perms"]["allow"] > 0),
                ("A deny list", lambda f: f["perms"]["deny"] > 0),
                ("A deny rule on secrets", lambda f: f["perms"]["secrets"]),
                ("A sandbox", lambda f: f["sandbox"]),
                ("Every MCP server of the project approved", lambda f: f["perms"]["mcp_all"]),
            ],
        ),
        (
            "security",
            "scanners",
            "Scanners called from CI",
            "Named in a GitHub Actions workflow. GitHub's own settings leave no file.",
            everyone,
            True,
            [(SCANNER_NAMES[k], is_in("scanners", k)) for k in SCANNER_NAMES],
        ),
        (
            "security",
            "sec_bots",
            "Security bots on pull requests",
            "%d or more of the latest %d review or pull request comments. Today only."
            % (MIN_BOT_COMMENTS, LATEST_ITEMS),
            everyone,
            True,
            None,
        ),
    ]
    out = []
    for lens_id, list_id, title, note, base, ranked, rows in lists:
        based = {lg: [r for r in view if base(r["now"])] for lg, view in views.items()}
        if rows is None:  # the bots, named by the API signals
            rows = [
                (label, None)
                for label in collections.Counter(x for r in based["pro"] for x in r["api"]["security_bots"])
            ]
        made = [
            {
                "label": label,
                **{
                    lg: share(
                        sum(1 for r in based[lg] if (test(r["now"]) if test else label in r["api"]["security_bots"])),
                        len(based[lg]),
                    )
                    for lg in views
                },
            }
            for label, test in rows
        ]
        made.sort(key=lambda row: (-row["pro"]["k"], -row["ladder"]["k"]))
        if ranked:
            made = [row for row in made if row["pro"]["k"]][:8]
        else:  # a row no repo of either league meets would be drawn empty
            made = [row for row in made if row["pro"]["k"] or row["ladder"]["k"]]
        out.append({"lens": lens_id, "id": list_id, "title": title, "note": note, "rows": made})
    return out


def lens_shift(views):
    """The lint and format tools at the first snapshot and today: a config file in the repo, or the tool in the root package.json.

    Over the whole view at both dates, as series() counts: a repo created since the first snapshot does not have the tool there.
    Each league carries its change in points between the two, as printed. The rows go from the largest share of the pro scene today
    to the smallest, a tie by the ladder's share today, as every list of the sections of Practices.
    """
    names = [
        ("oxlint", "Oxlint"),
        ("oxfmt", "Oxfmt"),
        ("biome", "Biome"),
        ("eslint", "ESLint"),
        ("prettier", "Prettier"),
        ("knip", "Knip"),
    ]
    at = lambda view, key, i: share(sum(1 for r in view if r["f"][i] and r["f"][i]["tool"][key]), len(view))
    two = lambda first, now: {"first": first, "now": now, "change": points(now["p"]) - points(first["p"])}
    rows = [
        {
            "id": key,
            "label": label,
            **{lg: two(at(view, key, 0), at(view, key, -1)) for lg, view in views.items()},
        }
        for key, label in names
    ]
    return sorted(rows, key=lambda row: (-row["pro"]["now"]["p"], -row["ladder"]["now"]["p"]))


def lens_left(view):
    """The tools the pro repos took out: those that had one at any snapshot and those of them that do not today."""
    rows = []
    for key, label, about in LENS_LEFT:
        ever, gone, when = departures(view, lambda r, key=key: [f and f[key] for f in r["f"]])
        now = sum(1 for r in gone if r["now"]["fast_lint"])
        row = {
            "id": key,
            "label": label,
            "field": "checks",
            "lens": "checks",
            "kind": "any",
            "about": about,
            "left": share(len(gone), ever),
            "stayed": stayed(view, lambda r, key=key: [f and f[key] for f in r["f"]]),
            "when": when,
            "switched": now,
        }
        # from 3 leavers, as left() and lens_departures() write theirs: with none it would read "all 0 run Oxlint, Oxfmt
        # or Biome today"
        if len(gone) >= 3:
            row["after"] = "%s run Oxlint, Oxfmt or Biome today" % (
                "all %d" % now if now == len(gone) else "%d of the %d" % (now, len(gone))
            )
        rows.append(row)
    return rows


def lens_block_readings(pro, by, rows):
    """Our reading of a lens practice in What moved and in What left, as two dicts by id, under the rules of readings():
    the first is about the last three months, the second about the whole history, and neither repeats the row's own figures."""
    then = -1 - BACK
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    cap = lambda text: text[0].upper() + text[1:]
    # as moves() counts them: a repo created since that has it today added it, its answers then being None
    pairs = [(r, r["f"][then], r["f"][-1]) for r in pro]
    added = lambda key: [(r, a) for r, a, b in pairs if b[key] and not has(a, key)]
    leavers = lambda key: departures(pro, lambda r: [f and f[key] for f in r["f"]])[1]
    move, stay = {}, {}

    rows_in = added("fast_lint")
    oxlint = sum(1 for r, _ in rows_in if r["now"]["tool"]["oxlint"])
    dropped = sum(1 for r, a in rows_in if has(a, "eslint") and not r["now"]["eslint"])
    if rows_in and oxlint == len(rows_in) and 2 * dropped > len(rows_in):
        move["fast_lint"] = "All %d that added one run Oxlint, and %d of them took ESLint out over the same %s." % (
            len(rows_in),
            dropped,
            months(BACK),
        )

    rows_in = added("threat_model")
    scanner = sum(1 for r, _ in rows_in if count("oss_scanner", tip_tree(r)["hits"].get("oss_scanner")) > 0)
    if scanner >= 3:
        move["threat_model"] = "%s new ones sit in .oss-scanner/, the folder of Anthropic's OSS Scanner." % cap(
            of_the(scanner, len(rows_in))
        )

    out = leavers("eslint")
    linted = sum(1 for r in out if r["now"]["ci_lint"])
    if out and 4 * linted >= 3 * len(out):
        stay["eslint"] = "The tool changed, the check stayed: %s still run a linter or a formatter in CI." % of_the(
            linted, len(out)
        )

    shown = {row["id"]: in_left(row) or in_stayed(row) for row in rows}
    move = {k: v for k, v in move.items() if shown_move(by[k]["pro"]["moves"])}
    stay = {k: v for k, v in stay.items() if shown.get(k)}
    for text in list(move.values()) + list(stay.values()):
        if len(text) > READING_MAX:
            raise ValueError("reading over %d characters (%d): %s" % (READING_MAX, len(text), text))
    return move, stay


def test_share(view):
    """Test files among code files, at the first snapshot and today, over the repos with MIN_CODE_FILES or more at both and a code
    file at every snapshot: a repo down to a file or two at one snapshot would give a share of 0 over 0."""
    part = lambda f: f["code"][0] / f["code"][1]
    kept = [
        r
        for r in view
        if all(f and f["code"][1] for f in r["f"])
        and min(r["f"][0]["code"][1], r["f"][-1]["code"][1]) >= MIN_CODE_FILES
    ]
    both = [(r["f"][0], r["f"][-1]) for r in kept]
    return {
        "n": len(kept),
        "first": round(statistics.median(part(a) for a, b in both), 3),
        "now": round(statistics.median(part(b) for a, b in both), 3),
        "up": sum(1 for a, b in both if part(b) > part(a)),
    }


def lens_readings(pro, by, gone, dates):
    """Our reading of a lens practice, by id: one sentence on what was counted in the pro scene, under the rules of readings().

    Each is written only while the fact it rests on holds; a practice with nothing sound to say gets none.
    """
    have = lambda key: [r for r in pro if r["now"][key]]
    among = lambda rows, test: sum(1 for r in rows if test(r["now"]))
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    cap = lambda text: text[0].upper() + text[1:]
    month = lambda i: AS_OF.replace(year=int(dates[i][:4]), month=int(dates[i][5:7]), day=1).strftime("%B %Y")
    first = lambda r, key: next(i for i, f in enumerate(r["f"]) if f and f[key])

    def wave(key, start, end):
        """Of the repos with a practice today, those that first had it in the snapshots of the months start to end.

        A snapshot is read on the 17th: one that first shows a practice says it came in the month before that day.
        """
        return sum(1 for r in have(key) if start <= dates[first(r, key)][:7] <= end)

    out = {}
    # ---------- checks
    silent = [r for r in pro if r["now"]["instructions_root"] and not r["now"]["says_tests"]]
    in_ci = among(silent, lambda f: f["ci_tests"])
    if silent and 2 * in_ci > len(silent):
        out["says_tests"] = (
            "%s root instruction files that name no test command sit in repos that run tests in CI."
            % cap(of_the(in_ci, len(silent)))
        )

    rows = have("checks_ext")
    told = among(rows, lambda f: f["says_tests"])
    if rows and 2 * told > len(rows):
        out["checks_ext"] = (
            "%s also name the test command in their instructions: the skill comes on top of the instruction."
            % cap(of_the(told, len(rows)))
        )

    rows = have("hook_checks")
    told = among(rows, lambda f: f["says_tests"])
    heavy = among(rows, lambda f: bool({"tests", "types"} & f["hook_runs"]))
    if rows and told == len(rows) and not heavy:
        out["hook_checks"] = (
            "All %d also name the test command in their instructions. None runs the tests or a type check: the hooks format and lint."
            % len(rows)
        )

    rows = have("fast_lint")
    beside = among(rows, lambda f: f["eslint"])
    switched = gone["eslint"]
    if rows and switched["left"]["k"] >= 3:
        out["fast_lint"] = (
            "%s still have ESLint beside it. %d of the %d repos that took ESLint out run one of the three today."
            % (cap(of_the(beside, len(rows))), switched["switched"], switched["left"]["k"])
        )

    rows = have("knip")
    fast = among(rows, lambda f: f["fast_lint"])
    if rows and 2 * fast > len(rows):
        out["knip"] = "%s also run Oxlint, Oxfmt or Biome: the two arrive in the same repos." % cap(
            of_the(fast, len(rows))
        )

    gain = {k: by[k]["pro"]["now"]["k"] - by[k]["pro"]["first"]["k"] for k in ("ci_tests", "ci_lint", "ci_types")}
    if gain["ci_types"] > max(gain["ci_tests"], gain["ci_lint"]):
        out["ci_types"] = "The old habit that moved most: %d pro repos in %s, %d today." % (
            by["ci_types"]["pro"]["first"]["k"],
            month(0),
            by["ci_types"]["pro"]["now"]["k"],
        )

    # ---------- security
    rows = have("cooldown")
    spring = wave("cooldown", "2026-04", "2026-06")
    if rows and 3 * spring > len(rows):
        out["cooldown"] = (
            "%s wrote it between mid-March and mid-June 2026, the weeks of the Trivy, axios and TanStack compromises."
            % (cap(of_the(spring, len(rows))))
        )

    rows = have("pinned")
    late = wave("pinned", "2026-04", "2026-06")
    if rows and 3 * late > len(rows):
        out["pinned"] = (
            "%s began between mid-March and mid-June 2026, the weeks of the Trivy and TanStack compromises."
            % (cap(of_the(late, len(rows))))
        )

    rows = have("zizmor")
    pins = among(rows, lambda f: f["pinned"])
    if rows and 2 * pins > len(rows):
        out["zizmor"] = "%s also pin their actions to a commit: the audit and the pinning go together." % cap(
            of_the(pins, len(rows))
        )

    agents = have("agent_in_ci")
    limited, anyone = among(agents, lambda f: f["fence_tools"]), among(agents, lambda f: "open" in f["fence"])
    shell = among(agents, lambda f: "bash" in f["fence"])
    if agents:
        out["fence_tools"] = "%s repos that run an agent in CI limit its tools%s.%s" % (
            cap(of_the(limited, len(agents))),
            "; %d more list them but allow every shell command" % shell if shell else "",
            " In %d, anyone can trigger it." % anyone if anyone else "",
        )

    rows = have("perm_rules")
    allow, deny = (
        among(rows, lambda f: f["perms"].get("allow", 0) > 0),
        among(rows, lambda f: f["perms"].get("deny", 0) > 0),
    )
    if rows and allow > deny:
        out["perm_rules"] = (
            "%s hold an allow list and %d a deny list: the shared file saves prompts more often than it forbids."
            % (cap(of_the(allow, len(rows))), deny)
        )

    rows = have("kept_from_agent")
    cursor = sum(
        1
        for r in rows
        if any(
            p.endswith(".cursorignore") for p in (tip_tree(r)["hits"].get("agent_ignore") or {"sample": []})["sample"]
        )
    )
    denied = among(rows, lambda f: bool(f["perms"].get("secrets")))
    if rows and 2 * cursor > len(rows):
        out["kept_from_agent"] = "%s commit a .cursorignore; %d deny secret files in their Claude Code settings." % (
            cap(of_the(cursor, len(rows))),
            denied,
        )

    spoken, tests = by["says_security"]["pro"]["now"]["k"], by["says_tests"]["pro"]["now"]["k"]
    if tests >= 2 * spoken:
        out["says_security"] = "%d pro repos speak of security in their instructions; %d name a test command." % (
            spoken,
            tests,
        )

    rows = have("threat_model")
    scanner = sum(1 for r in rows if count("oss_scanner", tip_tree(r)["hits"].get("oss_scanner")) > 0)
    since = min((first(r, "threat_model") for r in rows), default=0)
    if rows and since > 0:
        out["threat_model"] = "None before %s.%s" % (
            month(since),
            " %s sit in .oss-scanner/, the folder of Anthropic's OSS Scanner." % cap(of_the(scanner, len(rows)))
            if scanner >= 3
            else "",
        )
    return out


# The readings of the rows of Test and Secure. Each reads row_facts(), what one repo of a lens view gives them, so that
# the unit tests can hand them made-up repos.
# A git hooks path of pre-commit: its config, or prek's, which runs the same hooks
PRE_COMMIT = (".pre-commit-config", "prek.toml")
# The tool a lint rule of a repo's own is written for, by a word of its path, the first that matches
LINT_RULE_TOOLS = ("grit", "oxlint", "eslint", "semgrep")
# The day of an event of Secure's timeline (LENS_EVENTS, which gives its month) where a reading counts the days to it: the GitHub
# advisory GHSA-69fq-xp46-6x23, read on 2026-11-24, "On March 19, 2026, a threat actor used compromised credentials to publish a
# malicious Trivy v0.69.4 release, force-push 76 of 77 version tags in aquasecurity/trivy-action [...]"
EVENT_DAYS = {"trivy-action tags hijacked": "2026-03-19"}


def row_facts(r):
    """What the readings of Test and Secure read of one repo of a lens view (lens_view): its main language and its size, its lens
    answers today, the answers of features() today for the practices read as Build's are, the API's reviewers and security bots
    and its security block as read (rule types, protected, counts: no person), four path rules and two lens answers at every
    snapshot, the paths kept today of three rules, and the token and supply fields of the last snapshot."""
    sec = r["scan"]["snaps"][-1].get("sec") or {}
    hits = tip_tree(r)["hits"]
    kept = lambda rule: [p for p in (hits.get(rule) or {"sample": []})["sample"] if fp.still_valid(rule, p)]
    base = features(r["scan"], -1) or {}
    return {
        "language": LANGUAGES.get(r["language"], "Other"),
        "files": own_files(r),
        "now": r["now"],
        "base": {key: bool(base.get(key)) for key in ("ai_review_config", "ci_multi_os", "container_images")},
        "ai_review": r["api"]["ai_review"],
        "security_bots": r["api"]["security_bots"],
        "security": r["api"].get("security") or {},
        "rules": {
            rule: [bool(x) for x in rule_series(r, rule)]
            for rule in ("cypress", "playwright", "dependabot", "renovate")
        },
        "trivy": [bool(f and "trivy" in f["scanners"]) for f in r["f"]],
        "fuzz": [has(f, "fuzz_tests") for f in r["f"]],
        "paths": {rule: kept(rule) for rule in ("git_hooks", "custom_lint", "ai_review_config")},
        "token": sec.get("token") or [0, 0],
        "supply": set(sec.get("supply") or []),
    }


def checks_readings(pro, by, shown, dates):
    """The Insight of rows of Test, by id, over the row_facts() of the pro scene, under the rules of readings(): each only while the
    fact it rests on holds and the practices it names are on the page."""
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    cap = lambda text: text[0].upper() + text[1:]
    month = lambda i: month_name(dates[i], year=True, full=True)
    out = {}

    # Browser end-to-end tests: those that took Cypress out, and what they run today
    cypress = lambda f: f["rules"]["cypress"]
    then, now = sum(1 for f in pro if cypress(f)[0]), sum(1 for f in pro if cypress(f)[-1])
    left = [f for f in pro if any(cypress(f)) and not cypress(f)[-1]]
    switched = sum(1 for f in left if f["rules"]["playwright"][-1])
    if len(left) >= SHOWN_MOVE and 2 * switched > len(left) and now < then:
        out["e2e_browser"] = "Cypress went from %d pro repos to %d; %s that took it out run Playwright today." % (
            then,
            now,
            of_the(switched, len(left)),
        )

    # AI review configured: the API's reviewers against the config committed, and whose the configs are (REVIEW_FILES)
    reviewed = [f for f in pro if f["ai_review"]]
    configs = [f for f in pro if f["base"]["ai_review_config"]]
    both = sum(1 for f in reviewed if f["base"]["ai_review_config"])
    rabbit = sum(
        1
        for f in configs
        if any(
            REVIEW_FILES.get(p.rsplit("/", 1)[-1], "").startswith("CodeRabbit") for p in f["paths"]["ai_review_config"]
        )
    )
    if "ai_review" in shown and reviewed and 4 * both < len(reviewed) and 2 * rabbit > len(configs):
        out["ai_review_config"] = (
            "%s repos an AI reviewer comments on commit a review config; %s configs are CodeRabbit's."
            % (cap(of_the(both, len(reviewed))), of_the(rabbit, len(configs)))
        )

    # Git hooks, by main language: the gap holds in every size third (checked on the run of 2026-11-24)
    lang = lambda name: [f for f in pro if f["language"] == name]
    py, go = lang("Python"), lang("Go or Rust")
    hooked = lambda rows: sum(1 for f in rows if f["now"]["git_hooks"])
    pre = sum(
        1 for f in py if f["now"]["git_hooks"] and any(x in p for p in f["paths"]["git_hooks"] for x in PRE_COMMIT)
    )
    if min(len(py), len(go)) >= MIN_BASE and hooked(py) * len(go) > 2 * hooked(go) * len(py):
        out["git_hooks"] = "%s Python repos have them, %d through pre-commit; %s in Go or Rust." % (
            cap(of_the(hooked(py), len(py))),
            pre,
            of_the(hooked(go), len(go)),
        )

    # CI on Windows or macOS, by main language (the pro scene's: the ladder does not show the gap)
    compiled, web = [f for f in pro if f["language"] in ("Go or Rust", "Python")], lang("TypeScript or JS")
    a, b = (sum(1 for f in rows if f["base"]["ci_multi_os"]) for rows in (compiled, web))
    if min(len(compiled), len(web)) >= MIN_BASE and 2 * a * len(web) >= 3 * b * len(compiled):
        out["ci_multi_os"] = (
            "%s Go, Rust and Python repos run jobs on Windows or macOS, against %s in TypeScript or JS."
            % (
                cap(of_the(a, len(compiled))),
                of_the(b, len(web)),
            )
        )

    # Service containers in CI: a year or more within 3 repos from the first snapshot, then a rise of 10 or more
    item = by["ci_services"]["pro"]
    counts = [round(p * item["now"]["n"]) for p in item["series"]]
    flat = max(i for i in range(len(counts)) if max(counts[: i + 1]) - min(counts[: i + 1]) <= 3)
    if flat >= 12 and counts[-1] - counts[flat] >= 10:
        out["ci_services"] = "%d to %d pro repos from %s to %s, %d today." % (
            min(counts[: flat + 1]),
            max(counts[: flat + 1]),
            month(0),
            month(flat),
            counts[-1],
        )

    # Lint rules of their own: the tool each repo writes them for (a repo can write for several), and their size, said as size
    rows = [f for f in pro if f["now"]["custom_lint"]]
    tools = collections.Counter()
    for f in rows:
        tools.update({next((t for t in LINT_RULE_TOOLS if t in p.lower()), "other") for p in f["paths"]["custom_lint"]})
    sizes = sorted(f["files"] for f in pro)
    small = sum(1 for f in rows if f["files"] < sizes[len(sizes) // 3])  # the Small third of By context (contexts())
    if rows and tools["eslint"] > max(tools[t] for t in LINT_RULE_TOOLS if t != "eslint"):
        out["custom_lint"] = "%s write ESLint rules, %d Oxlint plugins and %d GritQL patterns%s." % (
            cap(of_the(tools["eslint"], len(rows))),
            tools["oxlint"],
            tools["grit"],
            "" if small else "; none sits in the smallest third by size",
        )
    return out


def security_readings(facts, by, shown, dates):
    """The Insight of rows of Secure, by id, over the row_facts() of both leagues, under the rules of readings(). The three practices
    read in GitHub's API today only (Pull request required, Private vulnerability reporting, Default branch protected) and the
    comments of code scanning have no history: their readings say no "when"."""
    pro, ladder = facts["pro"], facts["ladder"]
    of_the = lambda k, n: "all %d" % n if k == n else "%d of the %d" % (k, n)
    cap = lambda text: text[0].upper() + text[1:]
    month = lambda i, year=True: month_name(dates[i], year=year, full=True)
    split = lambda key: ([f for f in pro if f["now"][key]], [f for f in pro if not f["now"][key]])
    out = {}

    # Checkout keeps no token, and zizmor, whose artipacked audit flags a checkout that keeps its credentials
    rows, rest = split("checkout_no_token")
    a, b = (sum(1 for f in part if f["now"]["zizmor"]) for part in (rows, rest))
    if "zizmor" in shown and rows and rest and 2 * a > len(rows) and 4 * b * len(rows) < a * len(rest):
        out["checkout_no_token"] = (
            "%s run zizmor, whose audit flags a checkout that keeps its token; %d of the other %d do."
            % (cap(of_the(a, len(rows))), b, len(rest))
        )

    # Dependency bot: Renovate's rise, and where the repos that took Dependabot's file out went
    rule = lambda f, name: f["rules"][name]
    leavers = lambda name: [f for f in pro if any(rule(f, name)) and not rule(f, name)[-1]]
    dropped, gave_up = leavers("dependabot"), leavers("renovate")
    to_renovate = sum(1 for f in dropped if rule(f, "renovate")[-1])
    back = sum(1 for f in gave_up if rule(f, "dependabot")[-1])
    if len(dropped) >= SHOWN_MOVE and 2 * to_renovate > len(dropped):
        out["dep_bot"] = (
            "Renovate went from %d pro repos to %d; %s that took Dependabot's file out run Renovate today%s."
            % (
                sum(1 for f in pro if rule(f, "renovate")[0]),
                sum(1 for f in pro if rule(f, "renovate")[-1]),
                of_the(to_renovate, len(dropped)),
                "" if back else ", none the other way",
            )
        )

    # Pull request required: what the same rules of the default branch also require (the rule types the API lists)
    rows = split("pr_required")[0]
    types = collections.Counter(t for f in rows for t in f["security"].get("branch_rules") or [])
    checks, queue, copilot = types["required_status_checks"], types["merge_queue"], types["copilot_code_review"]
    if rows and 2 * checks > len(rows):
        out["pr_required"] = "%s also require status checks to pass and %d a merge queue%s." % (
            cap(of_the(checks, len(rows))),
            queue,
            "; in %d a rule asks Copilot to review" % copilot if copilot else "",
        )

    # Private vulnerability reporting: the repos that have published an advisory, with it on and off (partly mechanical: a
    # private report can become an advisory, so the sentence pairs the two and says no more)
    on, off = split("private_reporting")
    published = lambda part: sum(1 for f in part if (f["security"].get("advisories") or 0) > 0)
    if on and off and 2 * published(on) * len(off) > 3 * published(off) * len(on):
        out["private_reporting"] = "%s with it on have published a security advisory, against %s with it off." % (
            cap(of_the(published(on), len(on))),
            of_the(published(off), len(off)),
        )

    # Code scanning in CI: GitHub's code scanning comments in repos with no scanner in a workflow (default setup needs no
    # workflow file: GitHub's docs, "Setup types for code scanning", read on 2026-11-24)
    bot = dict(SECURITY_BOTS)["github-advanced-security"]
    quiet = sum(1 for f in pro if bot in f["security_bots"] and not f["now"]["scanners"])
    if quiet >= 3:
        out["code_scan"] = (
            "%d more pro repos get %s comments with no scanner of any kind in a workflow: default setup needs no workflow file."
            % (quiet, bot)
        )

    # Workflow tokens scoped: the share of its workflows a repo scopes the token in, the median over the repos with workflows
    shares = [ok / n for n, ok in (f["token"] for f in pro) if n]
    none = sum(1 for x in shares if x == 0)
    if len(shares) >= MIN_BASE and statistics.median(shares) >= 0.5:
        out["token_scoped"] = "The median pro repo scopes it in %s of its workflows%s." % (
            percent(statistics.median(shares)),
            "; %s with workflows scope it in none" % of_the(none, len(shares)) if none else "",
        )

    # Default branch protected: by an active ruleset (the API's rules of the branch) or protected with none ("protected", which
    # GitHub's docs say of a branch "protected by branch protections or rulesets"). Said of what the fields say: no "classic rule"
    def protection(rows):
        held = [f for f in rows if f["now"]["branch_protected"]]
        ruleset = sum(1 for f in held if f["security"].get("branch_rules"))
        return len(held), ruleset, len(held) - ruleset

    n, ruleset, other = protection(pro)
    _, l_ruleset, l_other = protection(ladder)
    if ruleset > other:
        out["branch_protected"] = "%s protect it with an active ruleset and %d without one%s." % (
            cap(of_the(ruleset, n)),
            other,
            "; on the ladder, %d and %d" % (l_ruleset, l_other) if l_ruleset < l_other else "",
        )

    # Secret scanning in CI or config: in a git hook, before the commit, or in CI (a scanner or a scanning step)
    rows = split("secret_scan_ci")[0]
    hook = lambda f: "secrets" in f["now"]["git_runs"]
    ci = lambda f: bool(f["now"]["scanners"] & set(fp.SCANNER_JOBS["secrets"])) or "secrets" in f["supply"]
    both = sum(1 for f in rows if hook(f) and ci(f))
    hooked = sum(1 for f in rows if hook(f))
    if "git_hooks" in shown and rows and 5 * hooked >= 2 * len(rows):
        out["secret_scan_ci"] = "%s scan in a git hook, before the commit, and %d in CI; %s." % (
            cap(of_the(hooked, len(rows))),
            sum(1 for f in rows if ci(f)),
            "none does both" if not both else "one repo does both" if both == 1 else "%d do both" % both,
        )

    # Dependency audit in CI: Trivy at the last snapshot before its action's tags were hijacked, and today. A date, no cause
    label = "trivy-action tags hijacked"
    event = next((m for m, where, name, _ in LENS_EVENTS if name == label), None)
    day = EVENT_DAYS[label]
    before = [i for i, d in enumerate(dates) if d < day]
    if event == day[:7] and before:
        i = before[-1]
        trivy = lambda k: sum(1 for f in pro if f["trivy"][k])
        gap = (dt.date.fromisoformat(day) - dt.date.fromisoformat(dates[i])).days
        rows = split("dep_audit_ci")[0]
        if trivy(-1) > trivy(i):
            out["dep_audit_ci"] = "%s run %s; %d did on %s, %s day%s before its action's tags were hijacked." % (
                cap(of_the(trivy(-1), len(rows))),
                SCANNER_NAMES["trivy"],
                trivy(i),
                long_day(dates[i]),
                words(gap),
                "" if gap == 1 else "s",
            )

    # SBOM: the repos that publish container images (Ship)
    rows, rest = split("sbom")
    a, b = (sum(1 for f in part if f["base"]["container_images"]) for part in (rows, rest))
    if "container_images" in shown and rows and rest and 2 * a * len(rest) > 3 * b * len(rows):
        out["sbom"] = "%s publish container images, against %d of the other %d." % (
            cap(of_the(a, len(rows))),
            b,
            len(rest),
        )

    # Fuzz tests: the step at the end of the series (the snapshots from which the count rose at every one), and the repos that
    # first show them after it began
    counts = [sum(1 for f in pro if f["fuzz"][i]) for i in range(len(dates))]
    start = min(i for i in range(len(counts)) if all(counts[k] < counts[k + 1] for k in range(i, len(counts) - 1)))
    rows = [f for f in pro if f["fuzz"][-1]]
    late = sum(1 for f in rows if not any(f["fuzz"][: start + 1]))
    if len(counts) - 1 - start >= BACK and 2 * late > len(rows):
        out["fuzz_tests"] = "%d pro repos had them in %s, %d today: %s first appear after mid-%s." % (
            counts[start],
            month(start),
            counts[-1],
            of_the(late, len(rows)),
            month(start, year=False),
        )
    return out


def arxiv_month(url):
    """The month a study was first sent to arXiv, "2026-08", read from its number (YYMM.NNNNN): the order of the outside evidence."""
    m = re.fullmatch(r"https://arxiv\.org/abs/(\d\d)(\d\d)\.\d{4,5}", url)
    if not m:
        raise ValueError("not an arXiv abstract: %s" % url)
    return "20%s-%s" % m.groups()


def lens(views, by, shown, rows, cards, dates):
    """The sections of Practices after Build (Test, Secure, Ship: LENSES): the practices of each on the page, what each is made of
    today, the sentences that quote the figures, and what the practice cards of its practices held. Also the report notes and the
    rows of What left they add. `by` holds every candidate counted (main()), `shown` the ids of those on the page, `rows` the rows of
    What left of the practices read in the lens views, every candidate's; the readings of the lens practices are written here, into
    `by` and `rows`. A section with no practice on the page is left out."""
    pro = views["pro"]
    gone = {row["id"]: row for row in lens_left(pro)}
    read = lens_readings(pro, by, gone, dates)
    facts = {lg: [row_facts(r) for r in view] for lg, view in views.items()}
    read.update(checks_readings(facts["pro"], by, shown, dates), **security_readings(facts, by, shown, dates))
    for key, text in list(LENS_ABOUT.items()) + [(row["id"], row["about"]) for row in gone.values()]:
        if len(text) > ABOUT_MAX:
            raise ValueError("about over %d characters (%d): %s" % (ABOUT_MAX, len(text), text))
    for key, text in read.items():
        if len(text) > READING_MAX:
            raise ValueError("reading over %d characters (%d): %s" % (READING_MAX, len(text), text))
    left_rows = rows + list(gone.values())
    move_read, left_read = lens_block_readings(pro, by, left_rows)
    for key, text in read.items():
        by[key]["reading"] = text
    for key, text in move_read.items():
        if by[key]["in_moves"]:
            by[key]["move_reading"] = text
    for row in left_rows:
        row["reading"] = left_read.get(row["id"])
    # the practices of a field on the page, in the order of PRACTICES
    of_field = lambda field: [by[key] for key in PRACTICES if key in shown and by[key]["field"] == field]
    lists, shift = lens_lists(views), lens_shift(views)
    tests = {lg: test_share(view) for lg, view in views.items()}
    n = {lg: len(view) for lg, view in views.items()}
    then = AS_OF.replace(year=int(dates[0][:4]), month=int(dates[0][5:7]), day=1).strftime("%B %Y")
    k = lambda key, when="now": by[key]["pro"][when]["k"]
    pct = percent
    tools = {row["id"]: row["pro"] for row in shift}
    agents = [r for r in pro if r["now"]["agent_in_ci"]]
    anyone = sum(1 for r in agents if "open" in r["now"]["fence"])
    # no cooldown written, but the package manager the root package.json pins waits by default
    unwritten = sum(1 for r in pro if r["now"]["waits_by_default"] and not r["now"]["cooldown"])
    ev = lambda level, text, study: {
        "level": level,
        "who": "Published study",
        "month": arxiv_month(STUDIES[study][1]),
        "text": text,
        "src": {"label": STUDIES[study][0], "url": STUDIES[study][1]},
    }
    line = lambda label, values, league="pro", item=None: dict(
        {"label": label, "league": league, "series": values}, **({"item": item} if item else {})
    )
    cell = lambda x: {"k": x["k"], "n": x["n"], "p": x["p"], "league": "pro"}
    ship = of_field("ship")
    # the most common practices of Ship in the pro scene, three at most, the ladder's count then the name for a tie
    ship_top = sorted(ship, key=lambda i: (-i["pro"]["now"]["k"], -i["ladder"]["now"]["k"], i["label"]))[:3]
    ship_today = [i["label"] for i in ship if not i["history"]]
    sections = [
        {
            "id": "checks",
            "label": LENSES[0][1],
            "about": LENSES[0][2],
            # written from the section's own practices, whichever they are, so that it still holds when one leaves the
            # page; then the share of test files in the median repo of each league, which is not a count of practices
            "intro": counts_line(of_field("checks"), then)
            + " In the median repo, test files went from %s to %s of the code files in the pro scene since %s, and from %s to %s "
            "on the ladder."
            % (
                pct(tests["pro"]["first"]),
                pct(tests["pro"]["now"]),
                then,
                pct(tests["ladder"]["first"]),
                pct(tests["ladder"]["now"]),
            ),
            "shift": {
                "title": "Lint and format tools, %s to today" % then,
                "note": "A config file in the repo, or the tool in the root package.json.",
                "rows": shift,
            },
            "left": list(gone.values()),
            "evidence": [
                ev(
                    "observed",
                    "In 2,303 agent context files from 1,925 repos, 75.9% give test procedures.",
                    "agent_readmes",
                ),
                ev(
                    "observed",
                    "In 4,882 pull requests written by agents, test changes come with 49.6% of those that change code "
                    "under test files.",
                    "test_coverage",
                ),
                ev(
                    "observed",
                    "In 86,156 test-file patches from agent pull requests, 80.2% contain weak or no explicit oracle signals.",
                    "weak_oracles",
                ),
            ],
            # under the heading "Not seen". Whether coverage is measured is a practice; what the tests cover is not read
            "blind": "Whether a test is any good, how much of the code the tests cover (that coverage is measured is read, not "
            "its figure), and a check that runs on another CI system, behind a task with a plain name (make check, a build) or "
            "only on a developer's machine. A test file is told by its folder or its name.",
        },
        {
            "id": "security",
            "label": LENSES[1][1],
            "about": LENSES[1][2],
            # written from the section's own practices, as Test's
            "intro": counts_line(of_field("security"), then),
            "evidence": [
                ev(
                    "observed",
                    "In 2,303 agent context files from 1,925 repos, security is specified in 14.8%.",
                    "agent_readmes",
                ),
                ev(
                    "observed",
                    "In 481 public CLAUDE.md files, only about 4-16% of the security rules found had a matching built-in "
                    "control.",
                    "do_not_deny",
                ),
                ev(
                    "observed",
                    "In a study of 117,062 dependency changes by agents and people, agents selected a version with a known "
                    "vulnerability in 2.46% of cases.",
                    "dep_decisions",
                ),
            ],
            "blind": "How the product is run (access, infrastructure, incident response), the settings GitHub shows only to a repo's "
            "admins (secret scanning, push protection, the rights of the workflows' token) and what a developer's machine enforces. "
            "pnpm 11, Yarn 4.15 and Dependabot wait before a new release by default: a cooldown counted here is one "
            "written in the repo.%s"
            % (
                " %d more pro repos write none and pin a pnpm or a Yarn that waits by default." % unwritten
                if unwritten
                else ""
            ),
        },
        {
            "id": "ship",
            "label": LENSES[2][1],
            "about": LENSES[2][2],
            # written from the section's own practices, whichever they are: the three most common in the pro scene, the kinds, and
            # what is read today only
            "intro": (
                "%s: %s of %d pro repos. "
                % (
                    "Most common in the pro scene" if len(ship_top) > 1 else "In the pro scene",
                    and_join(["%s in %d" % (i["label"], i["pro"]["now"]["k"]) for i in ship_top]),
                    ship_top[0]["pro"]["now"]["n"],
                )
                if ship_top
                else ""
            )
            + kinds_line(ship)
            + (" Read today only, in GitHub's API: %s." % and_join(ship_today) if ship_today else ""),
            "evidence": [],
            # what a deploy deploys: the workflows deploy the product, previews, docs and test setups alike, and the
            # scan cannot tell them apart
            "blind": "A release cut by hand or by another CI system, a deploy from a private repo or by a platform that deploys "
            "from git with no workflow, what a deploy in CI deploys (the product, a preview, the docs or a test setup), feature "
            "flags and rollbacks.",
        },
    ]
    for section in sections:
        # what the practice cards of its practices held (AI review's in Test), in the shape of Build's
        parts = card_parts([c for c in cards if c["id"] in shown and by[c["id"]]["field"] == section["id"]])
        section.update(reading=parts["reading"], details=parts["details"])
        section["evidence"] += parts["evidence"]
        # the outside evidence, the most recent study first; the tools that left, the largest share removed first
        section["evidence"].sort(key=lambda e: e["month"], reverse=True)
        if "left" in section:
            section["left"] = sorted(section["left"], key=lambda row: (-row["left"]["p"], -row["left"]["k"]))
        section["items"] = of_field(section["id"])
        section["events"] = [
            {"month": m, "label": label, "url": url} for m, where, label, url in LENS_EVENTS if where == section["id"]
        ]
        section["lists"] = [
            {key: value for key, value in l.items() if key != "lens"} for l in lists if l["lens"] == section["id"]
        ]
    # a section with no practice on the page is left out
    sections = [section for section in sections if section["items"]]
    on = lambda *keys: set(keys) <= set(shown)
    cap = lambda text: text[0].upper() + text[1:]
    month_of = lambda iso, year=True: AS_OF.replace(year=int(iso[:4]), month=int(iso[5:7]), day=1).strftime(
        "%B %Y" if year else "%B"
    )
    # Pinned actions: the JUMP snapshots in which the most pro repos pinned
    # their actions, the first such span on a tie, and what Secure's timeline dates in them, said as a date and nothing more
    pins, cools = ([x["k"] for x in series(pro, key)] for key in ("pinned", "cooldown"))
    jump = max(range(len(pins) - JUMP), key=lambda i: (pins[i + JUMP] - pins[i], -i))
    start, end = dates[jump], dates[jump + JUMP]
    hijack = next((m for m, where, label, _ in LENS_EVENTS if label == "trivy-action tags hijacked"), None)
    # what agents are told about tests against security (one note with the agent fenced); "far" while the one
    # is twice the other or more, and no note when tests are not ahead
    told = (
        "far more often"
        if k("says_tests") >= 2 * k("says_security")
        else "more often"
        if k("says_tests") > k("says_security")
        else None
    )
    skills_too = on("checks_ext", "security_ext")
    # the agent fenced, after: each clause while the practices it names are on the page. Agent in CI (Build) is the base of
    # Agent's tools limited in CI and not in the note's practices: the note is on Test and Secure
    fence = [
        (clause, keys)
        for clause, keys, needs in (
            ("%d commit permission rules for their agent" % k("perm_rules"), ["perm_rules"], ("perm_rules",)),
            (
                "of the %d that run one in CI, %d limit its tools and %d let anyone trigger it"
                % (len(agents), k("fence_tools"), anyone),
                ["fence_tools"],
                ("agent_in_ci", "fence_tools"),
            ),
        )
        if on(*needs)
    ]
    # Ship's note: "moved little" while its practices rose the least since the first snapshot of the
    # four fields' practices not specific to AI, on average; written while environments for CI jobs rose the most of Ship's
    rose = lambda i: points(i["pro"]["now"]["p"]) - points(i["pro"]["first"]["p"])
    mean_rise = {
        field: statistics.mean(rose(i) for i in of_field(field) if i["history"] and i["kind"] == "any")
        for field in FIELD_IDS
        if any(i["history"] and i["kind"] == "any" for i in of_field(field))
    }
    ship_read = [i for i in of_field("ship") if i["history"]]
    env = by["environments"]
    env_leads = env in ship_read and max(ship_read, key=rose) is env and rose(env) > 0
    little = "ship" in mean_rise and mean_rise["ship"] == min(mean_rise.values())
    log = by["changelog"]
    log_level = (
        log["pro"]["now"]["lo"] <= log["ladder"]["now"]["hi"] and log["ladder"]["now"]["lo"] <= log["pro"]["now"]["hi"]
    )
    ship_lines = [key for key in ("environments", "release_automation", "changelog") if on(key) and by[key]["history"]]
    went = lambda key: (by[key]["pro"]["first"]["k"], by[key]["pro"]["now"]["k"])
    ship_more = [
        text
        for text, key in (
            ("Releases cut by CI went from %d to %d" % went("release_automation"), "release_automation"),
            (
                "the changelog file went from %d to %d%s"
                % (
                    went("changelog")
                    + (
                        ": the ladder keeps one as often (%d of %d)"
                        % (log["ladder"]["now"]["k"], log["ladder"]["now"]["n"])
                        if log_level
                        else "",
                    )
                ),
                "changelog",
            ),
        )
        if key in ship_lines
    ]
    notes = [
        [
            "Pinned actions went from %d to %d pro repos in %s%s"
            % (pins[jump], pins[jump + JUMP], months(JUMP), " of %s" % start[:4] if start[:4] == end[:4] else ""),
            "%sBetween %s and %s, release cooldowns went from %d to %d. Today %d of %d pro repos pin their GitHub Actions to a "
            "commit and %d write a cooldown, against %d and %d in %s."
            % (
                "The trivy-action tags were hijacked in %s. " % month_of(hijack + "-01")
                if hijack and start[:7] <= hijack <= end[:7]
                else "",
                month_of(start, year=start[:4] != end[:4]),
                month_of(end),
                cools[jump],
                cools[jump + JUMP],
                pins[-1],
                n["pro"],
                cools[-1],
                pins[0],
                cools[0],
                then,
            ),
            "h-security",
            {
                "form": "trend",
                "title": "Share of the pro scene by month",
                "mark": jump,
                "lines": [
                    line(LENS_CHART_NAME.get(key, by[key]["label"]), by[key]["pro"]["series"], item=key)
                    for key in ("pinned", "cooldown")
                ],
            },
            ["pinned", "cooldown"],
        ],
        [
            "Oxlint, Oxfmt or Biome: from %d to %d pro repos" % (k("fast_lint", "first"), k("fast_lint")),
            "%d of %d pro repos run one of the three, up from %d in %s. ESLint went from %d to %d: %d of the %d that took it out "
            "run one of the three today."
            % (
                k("fast_lint"),
                n["pro"],
                k("fast_lint", "first"),
                then,
                tools["eslint"]["first"]["k"],
                tools["eslint"]["now"]["k"],
                gone["eslint"]["switched"],
                gone["eslint"]["left"]["k"],
            ),
            "h-checks",
            {
                "form": "trend",
                "title": "Share of the pro scene by month",
                "lines": [
                    line(by["fast_lint"]["label"], by["fast_lint"]["pro"]["series"], item="fast_lint"),
                    line("ESLint", [x["p"] for x in series(pro, "eslint")]),
                ],
            },
            ["fast_lint", "eslint"],
        ],
        [
            "Test files grew faster than the rest of the code",
            "Test files went from %s to %s of the code files in the median pro repo since %s. The share rose in %d of %d pro repos."
            % (pct(tests["pro"]["first"]), pct(tests["pro"]["now"]), then, tests["pro"]["up"], tests["pro"]["n"]),
            "h-checks",
            {
                "form": "dots",
                "title": "Pro repos read at both dates, one dot each, by the share of test files in their code",
                "n": tests["pro"]["n"],
                "parts": [
                    {"label": "share went up", "k": tests["pro"]["up"]},
                    {"label": "did not", "k": tests["pro"]["n"] - tests["pro"]["up"]},
                ],
            },
            # the share of test files is a figure of the lens, not a practice
            [],
        ],
        *(
            [
                [
                    "Agents are told how to test %s than what to keep safe" % told,
                    "%d pro repos name the test command in their instruction file, %d write a security rule there%s.%s"
                    % (
                        k("says_tests"),
                        k("says_security"),
                        "; %d have a skill or a command for tests, lint or CI, %d one for security"
                        % (k("checks_ext"), k("security_ext"))
                        if skills_too
                        else "",
                        " %s." % cap(", and ".join(clause for clause, _ in fence)) if fence else "",
                    ),
                    "h-security",
                    # every bar over the pro scene, the fenced agent's CI rows too (not over the repos that run an agent
                    # in CI), on the same scale; tests beside security, in what the file says, then in skills
                    {
                        "form": "bars",
                        "title": "Pro repos",
                        "value": "of",
                        "groups": [
                            [{"label": label, "cells": [cell(by[key]["pro"]["now"])]} for key, label in pair]
                            for pair in (
                                (("says_tests", "Test command"), ("says_security", "Security rules")),
                                (("checks_ext", "Skills for tests"), ("security_ext", "Skills for security")),
                            )
                            if skills_too or pair[0][0] == "says_tests"
                        ],
                    },
                    ["says_tests", "says_security"]
                    + (["checks_ext", "security_ext"] if skills_too else [])
                    + [key for _, keys in fence for key in keys],
                ]
            ]
            if told
            else []
        ),
        *(
            [
                [
                    cap(
                        "; ".join(
                            (["Shipping moved little"] if little else [])
                            + [
                                "environments for CI jobs doubled"
                                if env["pro"]["now"]["k"] >= 2 * env["pro"]["first"]["k"]
                                else "environments for CI jobs went from %d to %d pro repos"
                                % (env["pro"]["first"]["k"], env["pro"]["now"]["k"])
                            ]
                        )
                    ),
                    "%d pro repos run CI jobs in a GitHub environment, up from %d in %s.%s"
                    % (
                        env["pro"]["now"]["k"],
                        env["pro"]["first"]["k"],
                        then,
                        " %s." % cap(", and ".join(ship_more)) if ship_more else "",
                    ),
                    "h-ship",
                    {
                        "form": "trend",
                        "title": "Share of the pro scene by month",
                        "lines": [
                            line(LENS_CHART_NAME.get(key, by[key]["label"]), by[key]["pro"]["series"], item=key)
                            # two lines: a third of the same league is dotted as the second, and three run together on a
                            # screen 400px wide; the changelog is the sentence's alone
                            for key in ship_lines
                            if key != "changelog"
                        ],
                    },
                    ship_lines,
                ]
            ]
            if env_leads
            else []
        ),
    ]
    return {"sections": sections}, {
        "notes": notes,
        # the rows of What left of ESLint and Prettier: tools, not practices, ranked beside them
        "left": list(gone.values()),
        # at the end of the note of What left
        "left_note": "What an instruction file says is left out too: a file rewritten shorter reads as a removal.",
    }


def ordinal(n):
    """ "17th", "1st", "22nd"."""
    return "%d%s" % (n, "th" if 10 <= n % 100 < 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


# The block of the Method tab under which the page draws the invitation that ends the roster ("Does the rule miss a repo, or
# count one it should not? Get in touch"): the page takes the words and the link from the roster's paragraph, so they are typed
# once (the link is a mailto to the owner's address), and draws nothing more when `copy.method_invite` is absent.
METHOD_INVITE = "How a repo is picked"

# The public repo of the method: this code, some of its tests and the two panels, under the MIT licence. The Method tab links
# to it from its summary and from the block that says what it holds.
METHOD_REPO = "https://github.com/the-tech-meta/method"
METHOD_REPO_NAME = METHOD_REPO.split("github.com/")[1]  # "owner/repo", as the block names it

# The sections of the Method tab that hold blocks, in the order a reader follows, each the key of its list in `copy.method`
# and of its place on the page (`#m-<key>`): who is counted (under the two leagues' card), what is read, how a figure is
# shown, what it cannot say.
METHOD_SECTIONS = ("leagues", "read", "shown", "cannot")


def two_figures(x):
    """A count to two significant figures, with its thousands separator: 22,504 as "23,000", 277.5 as "280"."""
    n = int(round(x))
    return "{:,}".format(int(round(n, 2 - len(str(n)))) if n >= 100 else n)


def block(title, lead=None, items=None, rows=None, more=None, ordered=False, links=None, plain=False):
    """One block of the Method tab, as the page draws it (a title, then its parts in this order): `lead`, a sentence or
    two; `rows`, [term, definition] pairs, a small table, its terms in 600 (`plain`, in the text's weight); `items`,
    bullets (`ordered`, numbered); `more`, what is too long to show, in a closed disclosure: {"label", "lead", "parts":
    [{"title", "items"}]}, its lead and part titles optional; `links`, [words, address] pairs, the first time each words
    appear in the block's text made a link, in that order."""
    out = {"title": title}
    for key, value in (("lead", lead), ("rows", rows), ("items", items), ("more", more), ("links", links)):
        if value:
            out[key] = value
    if ordered:
        out["ordered"] = True
    if plain:
        out["plain"] = True
    return out


def block_text(b):
    """All the words of a block, in the page's order: what a link must be found in."""
    more = b.get("more") or {"label": "", "parts": []}
    return " ".join(
        [b.get("lead", "")]
        + [" ".join(row) for row in b.get("rows", [])]
        + b.get("items", [])
        + [more["label"], more.get("lead", "")]
        + [x for part in more["parts"] for x in [part.get("title") or ""] + part["items"]]
    )


def method(leagues, items, lens_items, left_rows, info, dates, candidates, gone):
    """The Method tab, for a human reader (short text, bullets, small tables, the long lists in a closed disclosure):
    its summary first, [term, text] pairs, then the blocks of each section of METHOD_SECTIONS. One subject per block,
    each said once, and nothing of when or how the page was made beyond what a reader needs to judge a figure. `items`
    and `lens_items` are the practices on the page, Build's and the other sections'; `candidates` every candidate
    counted, by id; `gone` the candidates not shown (under_bar). Returns (summary, {section: [block]})."""
    pro, ladder = leagues["pro"], leagues["ladder"]
    month_year = lambda iso: AS_OF.replace(year=int(iso[:4]), month=int(iso[5:7]), day=1).strftime("%B %Y")
    of = lambda x: "%d of %d" % (x["k"], x["n"])
    # The panels are fixed (series, moves): the repos of each league created since the first snapshot and since "then"
    new = {lg: (new_since(repos, 0), new_since(repos, -1 - BACK)) for lg, repos in leagues.items()}
    repos_of = lambda k, lg: "%d %s repo%s" % (k, lg, "" if k == 1 else "s") if k else "no %s repo" % lg
    or_none = lambda k: "%d" % k if k else "none"
    # a count the page writes in place of a percentage: the chip of What left with the largest base under MIN_BASE
    small = max((row["left"] for row in left_rows if row["left"]["n"] < MIN_BASE), key=lambda x: x["n"], default=None)
    # the practices where the pro share is above the ladder's, of every practice (the lens ones too)
    every = items + lens_items
    # the interval of one share the page shows, as Every number prints it in brackets: Skills on the ladder, or while Skills is not
    # on the page, the widest of the ladder's
    wide_of = next(
        (i for i in every if i["id"] == "skills"),
        max(every, key=lambda i: (i["ladder"]["now"]["hi"] - i["ladder"]["now"]["lo"], i["label"])),
    )
    wide = wide_of["ladder"]["now"]
    leads = sum(1 for i in every if i["pro"]["now"]["p"] > i["ladder"]["now"]["p"])
    # the ladder repos read for the lens practices (lens_view): one that could not be read is said
    lens_ladder = len([r for r in ladder if r["g"][-1] is not None])
    label = {key: i["label"] for key, i in candidates.items()}
    # the settings read from GitHub's API (security_settings): no history, read today only
    today_only = [i for i in lens_items if i["seen"] == "GitHub's API"]
    # the practices on the page by field, in the page's order, and the bar as the count of the pro scene it asks for
    on_page_in = [(name, k) for key, name in FIELDS for k in [sum(1 for i in every if i["field"] == key)] if k]
    # "12 are in Build, 20 in Test, 25 in Secure and 1 in Ship": a field with none is not a section of the page
    by_field = [
        "%d %s in %s" % (k, ("is" if k == 1 else "are") if j == 0 else "", name)
        for j, (name, k) in enumerate(on_page_in)
    ]
    by_field = [x.replace("  ", " ") for x in by_field]
    bar_k = next(k for k in range(len(pro) + 1) if passes_bar(k, len(pro)))
    # the practices read from GitHub's API on the page: no history, read today only
    api_on_page = [label[key] for key in API_PRACTICES if any(i["id"] == key for i in every)]
    # The rule both leagues are built by (panel.py, panel_rule.json): its conditions as panel.py numbers them, its
    # funnels, the owners it leaves out with their ties, and Runa Capital's own words on how the ROSS Index is built
    # (data/ross_index.json)
    rule, draw, picked = info["rule"], info["ladder"], info["pro"]
    if sorted(panel.LEFT_OUT) != info["left_out"]:
        raise ValueError(
            "the owners left out are not those the panels were built with: build them again (panel.py rule)"
        )
    ties = collections.Counter(e["tie"] for e in panel.LEFT_OUT.values())
    says = ROSS["says"]
    rule_words = {
        "organisation": "its owner is an organisation",
        "public": "it is public",
        "not_archived": "not archived",
        "not_fork": "not a fork",
        "created": "it was created before %s" % long_day(rule["created_before"]),
        "pushed": "it had a push in the last %d days" % rule["active_days"],
        "files": "it has %d files or more at the tip of its default branch" % rule["min_files"],
        "early_commits": "it had %d commits or more, merges left out, in the %d days before %s, the first snapshot: activity "
        "from before agents, not what the page measures"
        % (rule["min_early_commits"], rule["early_days"], long_day(rule["early_day"])),
        "not_vendor": "its owner is not one of the %d left out: the makers of the coding agents the page counts, and owners "
        "tied to them" % len(panel.LEFT_OUT),
    }
    # one bullet per number of the rule, its conditions joined: "It is public, not archived, not a fork."
    numbered = sorted({n for _, n, _ in info["conditions"]})
    conditions = [
        (lambda s: s[0].upper() + s[1:] + ".")(", ".join(rule_words[c] for c, m, _ in info["conditions"] if m == n))
        for n in numbered
    ]
    removed_words = {
        "organisation": "on a personal account",
        "public": "private",
        "not_archived": "archived",
        "not_fork": "a fork",
        "created": "created on %s or later" % long_day(rule["created_before"]),
        "pushed": "with no push in %d days" % rule["active_days"],
        "not_vendor": "an owner left out",
        "files": "under %d files" % rule["min_files"],
        "early_commits": "under %d early commits" % rule["min_early_commits"],
    }
    removed = lambda funnel: [
        "%s %s" % ("{:,}".format(f["removed"]), removed_words[f["condition"]]) for f in funnel if f["removed"]
    ]
    in_pro = sum(s["pro_left_out"] for s in draw["steps"])
    # Where each repo's history starts: the cut its scan carries (`since`), or OLD_SINCE for a scan made before scans carried one.
    # A snapshot whose COMMIT_DAYS days start before a repo's cut counts that repo's commits over fewer days, which is said.
    # A cut is an instant in UTC (2024-10-19T23:59:59Z), or a bare date for OLD_SINCE, read as its midnight in UTC.
    cuts = collections.Counter(
        r["scan"].get("since", OLD_SINCE) for repos in leagues.values() for r in repos
    ).most_common()
    cut_ts = lambda cut: int(
        dt.datetime.strptime(cut[:19] if "T" in cut else cut + "T00:00:00", "%Y-%m-%dT%H:%M:%S")
        .replace(tzinfo=dt.timezone.utc)
        .timestamp()
    )
    short = {
        cut: sum(1 for d in dates if end_of_day_ts(dt.date.fromisoformat(d)) - COMMIT_DAYS * 86400 < cut_ts(cut))
        for cut, _ in cuts
    }
    cut_back = month_year(cuts[0][0]) + "".join(
        " (%s for %d repo%s)" % (month_year(cut), k, "" if k == 1 else "s") for cut, k in cuts[1:]
    )
    cut_short = []
    for cut, k in cuts:
        if short[cut]:
            whose = (
                "The"
                if len(cuts) == 1
                else "For the %d repo%s cloned back to %s, the" % (k, "" if k == 1 else "s", month_year(cut))
            )
            cut_short.append(
                "%s %d days behind the first %s start before that, so %s agent-signed commits are counted over fewer days."
                % (
                    whose,
                    COMMIT_DAYS,
                    "snapshot" if short[cut] == 1 else words(short[cut]) + " snapshots",
                    "its" if short[cut] == 1 else "their",
                )
            )
    first, last = dt.date.fromisoformat(dates[0]), dt.date.fromisoformat(dates[-1])
    # the year a repo must be created before, as the summary says it: "2025" for 1 January, the day itself otherwise
    created = rule["created_before"]
    before = created[:4] if created[5:] == "01-01" else long_day(created)
    n_repos = len(pro) + len(ladder)

    summary = [
        # the candidates the bar lets through, in the four fields
        [
            "Measured",
            "How often %d practices show up in %d public repos: %d in the pro scene, %d on the ladder. They are what %s of "
            "the pro scene or more does. Under Practices, %s."
            % (
                len(every),
                n_repos,
                len(pro),
                len(ladder),
                percent(BAR),
                and_join(by_field),
            ),
        ],
        [
            "Who is in",
            "The pro scene is every repo the ROSS Index has named that passes one rule. The ladder is a random draw of "
            "other repos that pass it with %d stars or more." % rule["min_stars"],
        ],
        [
            "The rule",
            "An organisation's public repo, created before %s, pushed to in the last %d days, with %d files or more and "
            "already active in %s. Checked before any practice is read."
            % (before, rule["active_days"], rule["min_files"], month_year(rule["early_day"])),
        ],
        [
            "Detection",
            "Each practice is a fingerprint: a rule on file paths, file text, commit signatures or bot accounts. No "
            "language model reads anything. The code is open source.",
        ],
        [
            "Time span",
            # the last snapshot is "today", never its month: the issue is named by the month after it
            "Each repo's git history is replayed on the %s of each month, %s to today: %d snapshots. A few signals from "
            "the GitHub API are today's only." % (ordinal(last.day), first.strftime("%B %Y"), len(dates)),
        ],
        [
            "A figure",
            "The share of a league's repos that have a practice, observed and given with its base. It says what strong "
            "teams adopt and keep, not that a practice works.",
        ],
        [
            "Blind spots",
            "What leaves no trace in a public repo: a developer's machine, settings only admins can read, how a product "
            "is run, design and product work.",
        ],
        ["People", "None. The data holds repos, files and bot accounts only."],
    ]

    sections = {
        # who is counted, under the two leagues' card: where each league comes from, the rule, the fixed panel
        "leagues": [
            block(
                "Where the pro scene comes from",
                "The ROSS Index: Runa Capital's tables of open-source startups, %d quarterly and annual editions since %s. "
                "Every repo it has named that passes the rule is in, with no cut and no rank."
                % (len(ROSS["editions"]), ROSS["editions"][0]["id"][-4:]),
                items=[
                    "How it ranks, in the words of its methodology: “%s”" % says["rank"],
                    "What it keeps: “%s”" % says["select"],
                    "A startup, for the index, “%s” and “%s”." % (says["founded"], says["raised"]),
                ],
                links=[["ROSS Index", ROSS["url"]], ["methodology", ROSS["methodology"]]],
            ),
            block(
                "How the ladder is drawn",
                "A uniform draw from the repos that pass the same rule with %d stars or more." % rule["min_stars"],
                items=[
                    "Every creation day from %s to %s is put in a random order."
                    % (long_day(draw["first_day"]), long_day(draw["last_day"])),
                    "The days are taken in that order, and every repo created on them that passes is pooled, until there "
                    "are %d or more." % rule["ladder_size"],
                    "%d are drawn from the %s." % (len(ladder), "{:,}".format(draw["pool"])),
                ],
            ),
            # the rule of panel.py. The page draws the roster's invitation under this block (METHOD_INVITE)
            block(
                METHOD_INVITE,
                "By rule, the same for both leagues: never by hand, and never on the traces the page counts. A repo is in "
                "when it passes all %s, on the day the lists are made, before the scan." % words(len(numbered)),
                items=conditions,
                ordered=True,
                more={
                    "label": "What the rule left out",
                    "lead": "Each repo left out is counted under the first condition it fails.",
                    "parts": [
                        {
                            "title": "Pro scene",
                            "items": [
                                "%s repos named by the ROSS Index (%s names, read through GitHub, which follows a rename; %d "
                                "no longer answer)"
                                % ("{:,}".format(picked["repos"]), "{:,}".format(picked["names"]), picked["missing"]),
                                "%d pass" % picked["passed"],
                            ]
                            + removed(picked["funnel"]),
                        },
                        {
                            "title": "Ladder",
                            "items": [
                                "%s repos from %d creation days, with %d stars or more, a push in %d days, not archived"
                                % (
                                    "{:,}".format(draw["considered"] + in_pro),
                                    draw["days_taken"],
                                    rule["min_stars"],
                                    rule["active_days"],
                                ),
                                "%s pass" % "{:,}".format(draw["pool"]),
                            ]
                            + removed(draw["funnel"])
                            + (["%d already in the pro scene" % in_pro] if in_pro else []),
                        },
                        {
                            "title": "The %d owners left out" % len(panel.LEFT_OUT),
                            "items": [
                                "%d makers of a coding agent the page counts" % ties["maker"],
                                "%d companies one of them bought" % ties["bought"],
                                "%d named by us: a maker's parent, former name or former maker, or the maker of an agent the "
                                "page does not count" % ties["named"],
                            ],
                        },
                    ],
                },
            ),
            # the fixed panel: today's repos at every date, which can only lower a past share
            block(
                "Today's repos, at every date",
                "Each league is today's repos, followed back in time.",
                items=[
                    "A curve ends on today's figure.",
                    "The past shown is the past of today's repos, not of every repo alive then.",
                    "A repo created since a date counts there as without the practice, which can only lower a past share.",
                    "%s and %s were created since %s, %s and %s since %s, where What moved starts."
                    % (
                        repos_of(new["pro"][0], "pro").capitalize(),
                        repos_of(new["ladder"][0], "ladder"),
                        month_year(dates[0]),
                        or_none(new["pro"][1]),
                        or_none(new["ladder"][1]),
                        month_year(dates[-1 - BACK]),
                    )
                    if new["pro"][0] or new["ladder"][0]
                    else "No repo of either league was created since %s: the rule takes only repos created before %s."
                    % (month_year(dates[0]), long_day(rule["created_before"])),
                ],
            ),
        ],
        # what is read: the list of practices first, then how a repo is read
        "read": [
            block(
                "How the list is made",
                "A practice is a decision a team makes about how it works, that leaves a trace in the repo, that one sentence "
                "can say and a reader could copy.",
                items=[
                    "A tool chosen is not one: what its config holds is. Nor is a file nearly every repo has, such as a README, "
                    "a licence or a lockfile.",
                    "The bar: a practice is on the page when %s of the pro scene or more has it at the last snapshot, %d of its "
                    "%d repos. One under it comes on the day it crosses." % (percent(BAR), bar_k, len(pro)),
                    "%d candidates were counted, and %d are on the page: %s."
                    % (len(candidates), len(every), and_join(["%d in %s" % (k, name) for name, k in on_page_in])),
                    "The ladder takes no part in the choice, only in the comparison.",
                    "Adoption says how common a practice is, never how good.",
                ],
                more={
                    "label": "The candidates not on the page",
                    "parts": [
                        {"title": title, "items": ["%s: %s pro repos" % (row["label"], of(row["pro"])) for row in rows]}
                        for title, rows in (
                            ("Under the bar", [row for row in gone if row["why"] == "under the bar"]),
                            ("Kept off by our call", [row for row in gone if row["why"] == "off"]),
                        )
                        if rows
                    ],
                }
                if gone
                else None,
            ),
            block(
                "The %s fields" % words(len(FIELDS)),
                "Each practice is in one field, a section of Practices, and carries its name wherever it shows.",
                rows=[[name, FIELD_ABOUT[key]] for key, name in FIELDS],
            ),
            # why some of what a workflow holds is a practice and the rest is plumbing, which the list of practices
            # leaves out
            block(
                "CI: practice or plumbing",
                "Some of what a workflow holds is a decision about how checks run, which one sentence can say and a reader "
                "could copy: a new push cancels the run it makes stale, jobs have a time limit, dependencies are cached, pull "
                "requests wait in a merge queue.",
                items=[
                    "The rest is plumbing, not counted: how workflows are shared, chained, scheduled or triggered, what they "
                    "post or commit back, which runners they use. It grows with the size of a repo, and its trace does not say "
                    "its purpose.",
                    "Where the purpose can be read, the purpose is the practice: a release cut, a stale issue closed, a label "
                    "set.",
                ],
            ),
            block(
                "History is replayed",
                "The past is measured from each repo's own history, not remembered.",
                items=[
                    "Repos are cloned without file contents, back to %s." % cut_back,
                    # to today, not to the last snapshot's day: the page never names its month
                    "They are read on the %s of each month, from %s to today: %d snapshots."
                    % (ordinal(last.day), long_day(dates[0]), len(dates)),
                ]
                + cut_short
                # what makes "today" readable without a date: each issue scans every repo again, its whole history
                # included
                + [
                    "Each issue clones every repo again and reads all its snapshots anew, the earliest too: an issue's "
                    "figures are those of its own reading."
                ],
            ),
            # fingerprints.SHIPPED, SHIPPED_WORD and IN_TESTS; the share of test files is the checks section's (TEST_FILE)
            block(
                "Fingerprints, no model",
                "Each practice is a rule. No language model reads anything.",
                items=[
                    "A rule reads file paths, the text of a few files, commit signatures or bot accounts.",
                    "The files read: workflows, package and tool configs, agent settings, root instruction files.",
                    "A trace inside shipped or test material is not counted: vendored or built code, tests, fixtures, "
                    "templates, examples, demos, benchmarks. It is not the repo's own setup.",
                    "A test runner's config is the exception, and test files are counted for their share of the code.",
                ],
            ),
            # the thresholds of the practices that have one: the three of the agents, and those of the two sections. GitHub's own
            # actions are fingerprints.FIRST_PARTY_ACTIONS
            block(
                "Thresholds",
                "A practice with a threshold counts from it.",
                # the practices with a threshold that are on the page
                rows=[
                    [label[key], text]
                    for key, text in (
                        (
                            "agent_commits",
                            "%d or more in the %d days before a snapshot" % (MIN_SIGNED_COMMITS, COMMIT_DAYS),
                        ),
                        ("agent_prs", "%d or more of a repo's latest %d" % (MIN_AGENT_PRS, LATEST_ITEMS)),
                        (
                            "ai_review",
                            "%d or more comments by AI reviewer bots among its latest %d review and %d pull request comments"
                            % (MIN_REVIEW_COMMENTS, LATEST_ITEMS, LATEST_ITEMS),
                        ),
                        ("sec_bots", "%d or more recent comments" % MIN_BOT_COMMENTS),
                        (
                            "preview_deploys",
                            "%d or more comments by one host's preview bot among its latest %d review and %d pull request "
                            "comments" % (MIN_BOT_COMMENTS, LATEST_ITEMS, LATEST_ITEMS),
                        ),
                        (
                            "pinned",
                            "%s or more of a repo's third-party actions called by a full commit SHA"
                            % percent(COMPLIANT_SHARE),
                        ),
                        (
                            "token_scoped",
                            "%s or more of its YAML workflows scope their token" % percent(COMPLIANT_SHARE),
                        ),
                        (
                            "checkout_no_token",
                            "%s or more of its actions/checkout steps keep no token" % percent(COMPLIANT_SHARE),
                        ),
                    )
                    if any(i["id"] == key for i in every)
                ]
                + [
                    [
                        "Share of test files",
                        "compared over the repos with %d code files or more at both dates" % MIN_CODE_FILES,
                    ],
                ],
                items=[
                    "GitHub's own actions and those of the repo's own account are not a third party's.",
                    "A repo with no workflow, or no checkout step, has neither token practice.",
                ],
                # its terms in the text's weight
                plain=True,
            ),
            # what the GitHub API gives has no history: read as it is today, said with no day of ours
            block(
                "Today only",
                "Some signals come from the GitHub API, which keeps no history. They are read as they are today.",
                items=[
                    "%s." % and_join(api_on_page),
                    "Security bots, from recent pull request comments.",
                    "%s settings: %s."
                    % (
                        words(len(today_only)).capitalize(),
                        ", ".join(i["label"][0].lower() + i["label"][1:] for i in today_only),
                    ),
                ],
            ),
            block(
                "What a workflow runs, what a file says",
                items=[
                    "A check in CI is a command a GitHub Actions workflow runs. A script of the root package.json is "
                    "followed to the tool it calls.",
                    "An instruction file names a command when it writes one, or a tool's name in code formatting.",
                    "What a file says is on the chart, but not in What moved, What left or the Kept column: a file "
                    "rewritten shorter, or turned into a link to another folder, would read as a removal.",
                ],
            ),
            block(
                "Release dates",
                "On the History charts and on Build's timeline, releases are dated to the month from press coverage. On "
                "the timeline, each links to its source.",
                items=[
                    "Cursor's co-author trailer: from users' posts on Cursor's forum dated 27 January 2026.",
                    "Claude Code's AGENTS.md support, version 2.1.277: from InfoWorld, 21 September 2026.",
                ],
            ),
            # what the public repo holds and what it does not: the scans and data/meta.json are not in it. The page asks readers to
            # report a repo through the "Get in touch" link of its list of repos, so the block does not point to the repo's issues
            block(
                "Open source",
                "The method is in a public repo, %s, under the MIT licence." % METHOD_REPO_NAME,
                items=[
                    "It holds the code that picks the repos, scans them, reads the rules and computes every figure of "
                    "this page and the sentences that quote them, with some of its tests.",
                    "It holds both leagues, every repo by name, and the rule they were built by.",
                    "It does not hold the scans, the files read from GitHub's API or the data this page is drawn from. A "
                    "figure cannot be checked from the repo alone: it shows how the figure is computed, and scanning the "
                    "same repos again gives the figures of the day of that scan.",
                ],
                links=[[METHOD_REPO_NAME, METHOD_REPO]],
            ),
        ],
        # how a figure is shown
        "shown": [
            block(
                "Small samples, wide intervals",
                "With %d and %d repos, the intervals Every number gives in brackets are wide."
                % (len(pro), len(ladder)),
                items=[
                    "%s on the ladder, at %s (%s), can be anywhere from %s to %s."
                    % (wide_of["label"], pc(wide), of(wide), percent(wide["lo"]), percent(wide["hi"])),
                    "Pro moves are exact for this panel, not beyond it.",
                ],
            ),
            block(
                "Under %d repos, a count" % MIN_BASE,
                "A share counted on fewer than %d repos is too unsteady for a percentage: the page writes the count "
                "instead%s and draws no bar." % (MIN_BASE, ", such as %s," % of(small) if small else ""),
                items=[
                    "A row of a ranked list.",
                    "A chip of What left.",
                    "The Kept column of Every number.",
                    "The tooltip of a setup's usual kit.",
                ],
            ),
            block(
                "What the pro lead compares",
                "The pro scene leads on %d of the %d practices. Read the order of the gaps, not their size."
                % (leads, len(every)),
                rows=[
                    [
                        "Median stars",
                        "%s pro, %s ladder"
                        % (
                            two_figures(statistics.median(r["stars"] for r in pro)),
                            two_figures(statistics.median(r["stars"] for r in ladder)),
                        ),
                    ],
                    [
                        "Median files",
                        "%s pro, %s ladder"
                        % (
                            two_figures(statistics.median(r["facts"]["files"] for r in pro)),
                            two_figures(statistics.median(r["facts"]["files"] for r in ladder)),
                        ),
                    ],
                ],
                items=[
                    "The pro repos were ranked by Runa Capital on the growth of their stars; the ladder is a draw under the "
                    "same rule. The two differ in more than their practices.",
                    "A lead says what the pro repos do more often, not that a practice made them grow.",
                    "It is worked out from the counts, to one decimal under %d×." % LEAD_WHOLE,
                    "It is shown only when %d repos or more of each league have the practice. Under that, where a repo "
                    "more or less would swing it, the page gives the two counts." % MIN_LEAD,
                ],
            ),
            block(
                "A change in points",
                "The difference of the two shares as printed, each rounded to a whole percent, so the two always "
                "subtract to it.",
                items=["A change of less than a point between two different counts reads <1 pt."],
            ),
            block(
                "What left",
                "A practice present at an earlier monthly snapshot and absent today.",
                items=[
                    "The ranking holds what %d pro repos or more ever had and %s or more took out, by the share that took it out."
                    % (SHOWN_LEFT, words(SHOWN_MOVE)),
                    "What stayed holds what %d pro repos or more had %s ago or earlier, by the share that still has it, "
                    "where most still do." % (SHOWN_LEFT, "a year" if STAYED_BACK == 12 else months(STAYED_BACK)),
                    "The others are chips under Tried by a few.",
                    "ESLint and Prettier are ranked with the practices: tools most repos started from.",
                    "llms.txt is left out, and has no Kept share in Every number: it usually moves into the docs build, "
                    "which reads as a removal.",
                ],
            ),
            # the size of a repo is its own file count at the last snapshot (own_files)
            block(
                "Context slices",
                "Slices under %d repos are hidden." % MIN_BASE,
                rows=[
                    ["Size", "a repo's number of files at the last snapshot, in thirds of the pro scene"],
                    [
                        "Monorepo",
                        "a workspace file at the root (pnpm, Turborepo, Nx, Lerna, Rush, go.work), or a packages, apps or "
                        "crates directory",
                    ],
                    ["Language", "GitHub's main one"],
                ],
            ),
        ],
        # what it cannot say
        "cannot": [
            block(
                "Adopted is not the same as works",
                "What strong teams adopt and keep, not proof that a practice makes anyone faster.",
            ),
            block(
                "Evidence levels",
                items=[
                    "Pipeline figures are Observed.",
                    "Studies keep their own level, with figures from their abstracts.",
                    "Nothing is Reported or Tested yet.",
                ],
            ),
            block(
                "What the sections cannot see",
                items=[
                    "An agent used with no file committed, no signature and no bot account.",
                    "Rules, servers and models set in a tool's own settings, outside the repo.",
                    "Whether an instruction file is followed, and whether it helps.",
                    "The quality of a test, and how much of the code the tests cover: that coverage is measured is read, not "
                    "its figure.",
                    "CI systems other than GitHub Actions.",
                    "A check behind a task with a plain name.",
                    "The GitHub settings only a repo's admins can read.",
                    "A developer's machine.",
                    "Templates and settings an organisation shares from another repo.",
                    "A release cut by hand, a deploy by another system or by a platform with no workflow, what a deploy in CI "
                    "deploys, feature flags and rollbacks.",
                ]
                + (
                    # said only while a ladder repo could not be read for them
                    [
                        "%s ladder repo%s could not be read for most practices of Test and Secure: they count %d ladder "
                        "repos there."
                        % (
                            words(len(ladder) - lens_ladder).capitalize(),
                            "" if len(ladder) - lens_ladder == 1 else "s",
                            lens_ladder,
                        )
                    ]
                    if lens_ladder < len(ladder)
                    else []
                ),
            ),
            # security as a whole: what its practices cannot say, and the false matches the audit of their rules found
            block(
                "What a repo does not show of its security",
                "How the product is run: access to production, infrastructure, incident response, penetration tests. "
                "None of these practices says a repo is safe.",
                items=[
                    "A token made read-only in a repo's or an organisation's settings shows in no file, so %s counts fewer "
                    "repos than those whose token is limited." % label["token_scoped"],
                    "A code-owners file routes reviews and enforces none without a branch rule.",
                    "%s reads the rules of rulesets: a classic branch protection's own rules are not shown to outsiders."
                    % label["pr_required"],
                ],
                more={
                    "label": "What the rules miss or count wrongly",
                    "parts": [
                        {
                            "items": [
                                "Signing set in a release tool's own config is not seen.",
                                "A checkout inside an action of the repo's own is not seen.",
                                "A cargo deny step that names no advisories counts as a dependency audit.",
                                "So does a scanner named in an agent's prompt.",
                                "A product built to fuzz has fuzz folders of its own.",
                            ]
                        }
                    ],
                },
            ),
        ],
    }
    return summary, sections


# The tags after a report note's headline: the most a note carries. Past two, a tag for each field would only repeat the
# sentence under it.
MAX_TAGS = 2


# The fields, the sections of Practices, in the page's order, with their names. A practice's field is its field in PRACTICES, read at
# the call (field_of); the rows of What left that are not practices have theirs here: Build for the instruction files of one tool,
# Test for ESLint and Prettier
FIELDS = [("build", "Build")] + [(key, label) for key, label, _ in LENSES]
FIELD = dict({rule: "build" for rule, _ in TOOL_FILES}, **{key: "checks" for key, _, _ in LENS_LEFT})


def field_of(key):
    return PRACTICES[key][0] if key in PRACTICES else FIELD[key]


def guard_note(leagues, views, by, order):
    """The report note on What moved: how many of its first TOP_MOVES rows, `order`, guard CI (CI_GUARDS), named in that
    order with the pro repos that added each, and the organisations the repos that added one or more belong to. Not
    "seven of the ten biggest moves are not about AI": most practices on the page are not, so seven of ten is what
    chance gives (on the run of 2026-11-24, 62 of the 89 practices on the page were not about AI, and CI_GUARDS were 7
    of the 89). Written while two rows or more of the first are guards and rose; a list, as the note's only element, or
    none."""
    guards = [key for key in order[:TOP_MOVES] if key in CI_GUARDS and by[key]["pro"]["change"] > 0]
    if len(guards) < 2:
        return []
    lens_read = {key for key, _, _, _ in LENS_ITEMS}
    # the repos that added each, as moves() counts them: in the view the practice is read in
    added = {
        key: [
            r
            for r in (views if key in lens_read else leagues)["pro"]
            if r["f"][-1][key] and not has(r["f"][-1 - BACK], key)
        ]
        for key in guards
    }
    names = {r["name"] for repos in added.values() for r in repos}
    owners = {name.split("/")[0] for name in names}
    # a name in the sentence: its first letter lower-case but where its first word has another capital (GitHub)
    low = lambda label: label if any(c.isupper() for c in label.split()[0][1:]) else label[0].lower() + label[1:]
    return [
        [
            "%s of the %s practices that rose most in %s harden CI"
            % (words(len(guards)).capitalize(), words(TOP_MOVES), months(BACK)),
            "Pro repos that added each in %s: %s. The %d repos that added one or more belong to %d organisations."
            % (
                months(BACK),
                and_join(["%s %d" % (low(by[key]["label"]), len(added[key])) for key in guards]),
                len(names),
                len(owners),
            ),
            "h-moves",
            {
                "form": "bars",
                "title": "Pro repos that added it in %s" % months(BACK),
                "value": "of",
                "groups": [
                    [
                        {
                            "label": LENS_CHART_NAME.get(key, by[key]["label"]),
                            "id": key,
                            "cells": [
                                {"k": len(added[key]), "n": n, "p": round(len(added[key]) / n, 4), "league": "pro"}
                            ],
                        }
                        for key, n in ((key, by[key]["pro"]["now"]["n"]) for key in guards)
                    ]
                ],
            },
            guards,
        ]
    ]


def note_tags(section, practices):
    """A note's tags in words are the fields of the practices it is about, in the page's order; a note about no practice
    (a figure of a section) carries the field of the section it links to, if that is one. MAX_TAGS at most: past that,
    none."""
    keys = {field_of(key) for key in practices} if practices else {key for key, _ in FIELDS if "h-" + key == section}
    fields = [{"label": label, "field": key} for key, label in FIELDS if key in keys]
    return fields if len(fields) <= MAX_TAGS else []


def count_practice(key, label, history, what, views):
    """One candidate, counted over the views it is read in (the leagues for ITEMS, the lens views for LENS_ITEMS) as the page shows
    a practice: its share today, and with a history its share at every snapshot, at the first, kept and moved; with its field and its
    kind (PRACTICES), what it is (ABOUT) and where it is read. Every candidate is counted, on the page or not."""
    field, kind, _ = PRACTICES[key]
    item = {
        "id": key,
        "label": label,
        "field": field,
        # the section the page draws it in, for a practice outside Build (the key the page reads)
        **({"lens": field} if field != "build" else {}),
        "kind": kind,
        "history": history,
        "what": what,
        "seen": SEEN_IN.get(key) or LENS_SEEN.get(key, "repo files"),
        "about": ABOUT.get(key) or LENS_ABOUT[key],
        # beyond its section: a dot on the map but for the two files the instruction file covers there (OFF_MAP), a row in What
        # moved and in What left but for what is read from a file's text (LENS_TEXT_READ), a Kept share in Every number but for
        # what moves into a docs build or is read from a text (NO_KEEP_RATE)
        "map": key not in OFF_MAP,
        "in_moves": history and key not in LENS_TEXT_READ,
        "sticks": key not in NO_KEEP_RATE and key not in LENS_TEXT_READ,
    }
    for lg, view in views.items():
        if history:
            s = series(view, key)
            item[lg] = {
                "now": s[-1],
                "first": s[0],
                "series": [x["p"] for x in s],
                "kept": retention(view, key),
                "moves": moves(view, key),
                "change": change([x["p"] for x in s]),
            }
        else:
            item[lg] = {"now": share(sum(1 for r in view if r["now"][key]), len(view))}
    item["lead"] = lead(item["pro"]["now"], item["ladder"]["now"])
    item.update(reading=None, move_reading=None)
    return item


def on_page(item):
    """A candidate is on the page when it is on and BAR of the pro scene or more has it at the last snapshot."""
    return PRACTICES[item["id"]][2] and passes_bar(item["pro"]["now"]["k"], item["pro"]["now"]["n"])


def under_bar(candidates):
    """The candidates counted and not shown, for the Method tab and meta.json's `under_bar`: each with its field, kind,
    its counts today, the most pro repos that had it at one snapshot and the pro repos that ever had it (What left's
    base), and why it is not shown."""
    out = []
    order = [key for key, _ in FIELDS]
    for i in sorted(candidates, key=lambda i: (order.index(i["field"]), -i["pro"]["now"]["k"], i["label"])):
        if on_page(i):
            continue
        # a share of the series back to its count: the base is fixed (series)
        k = lambda x, n=i["pro"]["now"]["n"]: round(x * n)
        out.append(
            {
                "id": i["id"],
                "label": i["label"],
                "field": i["field"],
                "kind": i["kind"],
                "pro": i["pro"]["now"],
                "ladder": i["ladder"]["now"],
                "peak": max(map(k, i["pro"]["series"])) if i["history"] else i["pro"]["now"]["k"],
                "why": "off" if not PRACTICES[i["id"]][2] else "under the bar",
            }
        )
    return out


def card_parts(cards):
    """What the practice cards give the section their practices are in: the reading of each (the Insight of its row), the published
    studies they quote (the section's outside evidence, the most recent first, the rule of every section), and the rest of each card
    (its row's details: for whom, the meta, how the pros build it, the skills' jobs, files to open, the alternatives, what changed,
    and the sentences of this panel's own, Observed)."""
    if any(e["who"] != "This panel" for c in cards for e in c["evidence"] if not e["src"]):
        raise ValueError("a card's claim with no source is not this panel's")
    return {
        "reading": {c["id"]: c["reading"] for c in cards},
        "evidence": [dict(e, month=arxiv_month(e["src"]["url"])) for c in cards for e in c["evidence"] if e["src"]],
        "details": {
            c["id"]: dict(
                {
                    key: c[key]
                    for key in ("for", "say", "build", "jobs", "jobs_note", "examples", "alternatives", "notes")
                    if key in c
                },
                panel=[e["text"] for e in c["evidence"] if not e["src"]],
            )
            for c in cards
        },
    }


def and_join(words_):
    """ "a", "a and b", "a, b and c"."""
    return "%s and %s" % (", ".join(words_[:-1]), words_[-1]) if len(words_) > 1 else "".join(words_)


def kinds_line(items):
    """How many of a section's practices are made for coding agents, in a sentence; the others are not counted in words.
    Build's and Ship's intros, and Test's and Secure's through counts_line."""
    agent = sum(1 for i in items if i["kind"] == "agent")
    if len(items) == 1:
        return "Its one practice is %smade for coding agents." % ("" if agent else "not ")
    if agent in (0, len(items)):
        return (
            "All %d practices here are made for coding agents."
            if agent
            else "None of the %d practices here is made for coding agents."
        ) % len(items)
    return "Of the %d practices here, %d %s made for coding agents." % (
        len(items),
        agent,
        "is" if agent == 1 else "are",
    )


# The intros of Test and Secure count the practices of their section, whichever they are, and name none: a practice that
# leaves the page, or joins it, changes the counts and the sentence stays true.
LENS_GAIN = 10  # "gained 10 points or more": the change of a practice's pro share since the first snapshot, as the page prints it


def counts_line(items, then):
    """A section's intro from its practices alone: how many are made for coding agents, how many are in more than half of the pro
    repos today, and how many of those read since the first snapshot (`then`, its month) gained LENS_GAIN points or more of the
    pro scene. No practice is named; one practice, or none, has its own words."""
    if not items:
        return ""
    or_none = lambda x: "%d" % x if x else "none"
    agent = sum(1 for i in items if i["kind"] == "agent")
    half = sum(1 for i in items if 2 * i["pro"]["now"]["k"] > i["pro"]["now"]["n"])
    read = [i for i in items if i["history"]]
    gained = sum(1 for i in read if points(i["pro"]["now"]["p"]) - points(i["pro"]["first"]["p"]) >= LENS_GAIN)
    gain = "gained %d points or more in the pro scene" % LENS_GAIN
    if len(items) == 1:
        one = items[0]["pro"]["now"]
        return "Its one practice is %smade for coding agents, and is in %d of %d pro repos.%s" % (
            "" if agent else "not ",
            one["k"],
            one["n"],
            " Since %s it has %s%s." % (then, "" if gained else "not ", gain) if read else "",
        )
    kinds = kinds_line(items)
    since = ""
    if len(read) == 1:
        since = " The one read since %s has %s%s." % (then, "" if gained else "not ", gain)
    elif read:
        since = " %s %s %s %s." % (
            "Since %s," % then if len(read) == len(items) else "Of the %d read since %s," % (len(read), then),
            or_none(gained),
            "has" if gained == 1 else "have",
            gain,
        )
    return "%s %s %s in more than half of the pro repos.%s" % (
        kinds,
        or_none(half).capitalize(),
        "is" if half == 1 else "are",
        since,
    )


# The sentence of each field, in the page's order
FIELD_ABOUT = dict(
    {
        "build": "How the work is set up and done: the files, conventions and agents the people writing a change rely on."
    },
    **{key: about for key, _, about in LENSES},
)


# Build, the first section of Practices: its practices are M.items; this holds what they do not: the section's
# sentences, the first snapshot of each practice, the dated events with their sources, and what the practice cards of
# its practices hold (the page draws no card: their studies are the section's outside evidence, the rest opens in the
# row of its practice).
BUILD_THIN = 0.2  # the intro counts the practices under this share of the pro scene: "fewer than one pro repo in five"


def build_section(items, cards, dates):
    by = {i["id"]: i for i in items}
    or_none = lambda x: "%d" % x if x else "none"
    thin = sum(1 for i in items if i["pro"]["now"]["p"] < BUILD_THIN)
    # the three agent practices the intro follows from the first snapshot, while all three are in the section
    agents = ("instructions", "agent_commits", "skills")
    k = lambda key, when="now": by[key]["pro"][when]["k"]
    parts = card_parts(cards)
    return {
        "id": "build",
        "label": "Build",
        "about": FIELD_ABOUT["build"],
        "intro": (
            "In %s, %s of %d pro repos had an agent instruction file, %s signed commits with an agent and %s had skills; "
            "today %d, %d and %d do. "
            % (
                month_name(dates[0], year=True, full=True),
                or_none(k("instructions", "first")),
                by["instructions"]["pro"]["now"]["n"],
                or_none(k("agent_commits", "first")),
                or_none(k("skills", "first")),
                k("instructions"),
                k("agent_commits"),
                k("skills"),
            )
            if all(key in by for key in agents)
            else ""
        )
        + kinds_line(items)
        + " %s %s in fewer than one pro repo in five." % (or_none(thin).capitalize(), "is" if thin == 1 else "are"),
        "blind": "An agent used with no file committed, no signature and no bot account; rules, servers and models set in a tool's "
        "own settings or on a developer's machine; whether an instruction file is followed, and whether it helps; templates "
        "and settings an organisation shares from another repo or keeps in GitHub's settings.",
        "events": [{"month": m, "label": label, "url": url} for m, label, url in EVENTS],
        "first": {i["id"]: {lg: i[lg]["first"] for lg in ("pro", "ladder")} for i in items if i["history"]},
        # the readings of the cards: the Insight of their practice's row
        "reading": parts["reading"],
        # the published studies the cards quoted, the most recent first (the rule of Test and Secure), each with its month
        "evidence": sorted(parts["evidence"], key=lambda e: e["month"], reverse=True),
        "details": parts["details"],
    }


def main(args):
    dates = [d.isoformat() for d in snapshot_dates()]
    leagues = {name: load(name) for name in ("pro", "ladder")}
    # the repos whose snapshots were read for the lens practices, with their answers in the place of the practices'
    views = {lg: lens_view(repos) for lg, repos in leagues.items()}
    defined = [i[0] for i in ITEMS] + [i[0] for i in LENS_ITEMS]
    if len(set(defined)) != len(defined) or set(defined) != set(PRACTICES):
        raise ValueError("PRACTICES must hold every practice of ITEMS and LENS_ITEMS once, and no other")
    if any(field not in FIELD_IDS or kind not in KINDS for field, kind, _ in PRACTICES.values()):
        raise ValueError("a practice of PRACTICES has a field or a kind that is not one of FIELD_IDS or KINDS")
    # every candidate, counted over the repos it is read in, on the page or not
    read_items = [count_practice(key, label, history, what, leagues) for key, label, history, what in ITEMS]
    read_lens = [count_practice(key, label, history, what, views) for key, label, history, what in LENS_ITEMS]
    candidates = read_items + read_lens
    by = {i["id"]: i for i in candidates}
    shown = {i["id"] for i in candidates if on_page(i)}
    for key, text in ABOUT.items():
        if len(text) > ABOUT_MAX:
            raise ValueError("about over %d characters (%d): %s" % (ABOUT_MAX, len(text), text))

    info = read_json(DATA / "panel_rule.json")  # the build of both panels: the day, the rule, the funnels, the draw
    models = model_history(leagues)
    kit_lists = kit(leagues)
    # a setup's usual kit: the agent practices on the page that it reads in the trees (the Setups are agent setups)
    build_rows = builds(leagues, [k for k in LABEL if k in shown and PRACTICES[k][1] == "agent" and k not in OFF_MAP])
    # the pro scene's only: the ladder's size thirds are far smaller (its Large starts under the pro's Small cap), so
    # its table would not compare. The sentences may quote a practice of CONTEXT_ITEMS that is not on the page; the
    # table holds those on it
    ctx_all = {"pro": contexts(leagues["pro"], CONTEXT_ITEMS + CONTEXT_NOTES)}
    ctx = {
        "pro": dict(
            ctx_all["pro"],
            rows=[row for row in ctx_all["pro"]["rows"] if row["id"] in shown and row["id"] in CONTEXT_ITEMS],
        )
    }
    # What left: a row for every candidate that can have one, the instruction files of one tool, then ESLint and Prettier (lens())
    rows, lens_rows = left(leagues["pro"], read_items, TOOL_FILES), left(views["pro"], read_lens)
    # what a row's leavers have today names another practice: said only while that practice is on the page
    for row in rows + lens_rows:
        if "after" in row and AFTER_NAMES.get(row["id"], row["id"]) not in shown:
            del row["after"]
    jobs = skill_jobs(leagues["pro"])
    practice_cards = cards(leagues, candidates, ctx_all, rows, jobs, kit_lists, build_rows, dates, shown)
    move_read, left_read = readings(leagues, read_items, rows, dates, shown)
    for key, text in move_read.items():
        by[key]["move_reading"] = text
    for row in rows:
        row["reading"] = left_read.get(row["id"])
    # Test, Secure and Ship. Their practices are in their own sections, and also on the map and in What moved (the page reads them
    # from the lens), and their removals are ranked in What left with the others, so the report note on what was taken out most
    # counts them. Their notes follow the report's own.
    # the Insight of a row of Build and Ship: Build's beside the cards' readings (build_section), the others' on the practice
    row_read = row_readings(leagues, dates, shown)
    for key in [k for k in row_read if PRACTICES[k][0] != "build"]:
        by[key]["reading"] = row_read.pop(key)
    lenses, more = lens(views, by, shown, lens_rows, practice_cards, dates)
    all_rows = rows + lens_rows + more["left"]
    # what the page shows of What left: the practices on it, the instruction files of one tool, ESLint and Prettier
    on_left = shown | {rule for rule, _ in TOOL_FILES} | {key for key, _, _ in LENS_LEFT}
    left_rows = [row for row in all_rows if row["id"] in on_left]
    items = [by[key] for key in PRACTICES if key in shown and by[key]["field"] == "build"]
    lens_items = [i for s in lenses["sections"] for i in s["items"]]
    # the rows of What moved, in their order: the practices and the lens practices that may move
    order = moved(items + lens_items)
    sentences = copy(leagues, candidates, info, models, ctx_all, left_rows, jobs, dates, shown)
    # a note about a practice that is not on the page goes with it
    sentences["notes"] = [
        note
        for note in sentences["notes"] + guard_note(leagues, views, by, order) + more["notes"]
        if set(note[4]) <= on_left
    ]
    sentences["notes"] = [
        note[:4] + [{"practices": note[4], "tags": note_tags(note[2], note[4])}] for note in sentences["notes"]
    ]
    gone = under_bar(candidates)
    # with the pro repos that ever had it at a snapshot, What left's base, over the repos it is read in
    lens_read = {key for key, _, _, _ in LENS_ITEMS}
    for row in gone:
        pro = (views if row["id"] in lens_read else leagues)["pro"]
        row["ever"] = (
            departures(pro, lambda r, key=row["id"]: [f and f[key] for f in r["f"]])[0]
            if by[row["id"]]["history"]
            else None
        )
    sentences["method_short"], sentences["method"] = method(
        leagues, items, lens_items, left_rows, info, dates, by, gone
    )
    if tuple(sentences["method"]) != METHOD_SECTIONS:
        raise ValueError("the sections of the Method tab are not METHOD_SECTIONS, in order")
    blocks = [b for section in sentences["method"].values() for b in section]
    titles = [b["title"] for b in blocks]
    if len(set(titles)) != len(titles):
        raise ValueError("two blocks of the Method tab share a title")
    for b in blocks:
        text = block_text(b)
        if any(words not in text for words, _ in b.get("links", [])):
            raise ValueError("a link of the Method tab names words its block does not hold: %s" % b["title"])
    if METHOD_INVITE not in titles:
        raise ValueError("the invitation names a block of the Method tab that does not exist")
    sentences["method_invite"] = METHOD_INVITE
    # the summary's links, the blocks' way: [words, address], the first time the words appear in its texts, in order
    sentences["method_short_links"] = [["open source", METHOD_REPO]]
    if any(
        words not in " ".join(text for _, text in sentences["method_short"])
        for words, _ in sentences["method_short_links"]
    ):
        raise ValueError("a link of the Method tab's summary names words it does not hold")
    build = build_section(
        items, [c for c in practice_cards if c["id"] in shown and by[c["id"]]["field"] == "build"], dates
    )
    build["reading"] = dict(row_read, **build["reading"])
    sentences["left"] += " " + more["left_note"]
    sentences.update(left_copy(dates))
    sentences.update(span_copy(BACK, SHOWN_MOVE))
    write_json(
        DATA / "meta.json",
        {
            # the day the data were read: the last snapshot's
            "as_of": AS_OF.isoformat(),
            # the issue, as the page prints it: the month and year it is published under, its number and its day (not
            # the day its data were read)
            "issue": ISSUE_DATE.strftime("%B %Y"),
            "issue_n": ISSUE_N,
            "issue_date": ISSUE_DATE.isoformat(),
            "dates": dates,
            # the snapshots between "then" and now, which the page counts back from today (its tails, its moves)
            "back": BACK,
            # under this base a share is a count on the page, with no percentage and no bar
            "min_base": MIN_BASE,
            # What left ranks the practices that this many pro repos or more ever had; the others are chips
            "shown_left": SHOWN_LEFT,
            # each section of Practices shows this many of its practices, the rest behind a button
            "shown_practices": SHOWN_PRACTICES,
            # a list cut to its first rows shows whole when the cut would hide fewer rows than this
            "cut_min": CUT_MIN,
            # the bar a candidate passes to be on the page (a share of the pro scene at the last snapshot), and the candidates
            # counted and not shown, with why
            "bar": BAR,
            "under_bar": gone,
            "items": items,
            "bands": BANDS,
            "models": models,
            "kit": kit_lists,
            "events": [{"month": m, "label": label} for m, label, _ in EVENTS],
            "builds": build_rows,
            "left": left_rows,
            # the rows of What left and of What stayed, as ids in their order (left_lists)
            "lefts": left_lists(left_rows),
            "contexts": ctx,
            # the first section of Practices, Build: the practices of the map, the timeline of their releases, the outside
            # evidence and what the three practice cards held
            "build": build,
            "evidence": evidence(
                build["evidence"] + [e for s in lenses["sections"] for e in s["evidence"]],
                len(items) + len(lens_items),
                leagues,
            ),
            "roster": roster(leagues["pro"]),
            # the panels are fixed: every share over time is over n, and "new" says how many of the n were created since the first
            # snapshot and since "then" (they count there as not having a practice)
            "leagues": {
                name: {"n": len(repos), "new": {"first": new_since(repos, 0), "then": new_since(repos, -1 - BACK)}}
                for name, repos in leagues.items()
            },
            "copy": sentences,
            "lens": lenses,
            # the rows of What moved, in their order: the practices and the lens practices that may move
            "moved": order,
        },
    )

    print("leagues:", {name: len(repos) for name, repos in leagues.items()})
    for item in items:
        line = "%-28s pro %5.1f%%  ladder %5.1f%%" % (
            item["label"],
            100 * item["pro"]["now"]["p"],
            100 * item["ladder"]["now"]["p"],
        )
        if item["history"]:
            line += "   %dmo pro %+5.1f (+%d/-%d)  kept %s" % (
                BACK,
                100 * (item["pro"]["now"]["p"] - item["pro"]["series"][-1 - BACK]),
                item["pro"]["moves"]["gained"],
                item["pro"]["moves"]["lost"],
                "%d/%d" % (item["pro"]["kept"]["k"], item["pro"]["kept"]["n"]),
            )
        print(line)
    if args.audit:
        print_audit(leagues)
    if args.matrix:
        print_matrix(leagues)


def print_matrix(leagues):
    keys = [k for k in LABEL]
    print("\n" + " ".join(k[:4] for k in keys))
    for r in sorted(leagues["pro"], key=lambda r: -sum(r["now"][k] for k in keys)):
        print(" ".join("  x " if r["now"][k] else "  . " for k in keys), build_of(r["now"])[:5], r["name"])
    for lg, repos in leagues.items():
        print(lg, collections.Counter(build_of(r["now"]) for r in repos).most_common())
    print("median lines", {lg: median_lines(repos) for lg, repos in leagues.items()})
    for what, pick in (
        (
            "skills",
            lambda r: [
                p.split("/skills/")[-1].split("/")[0]
                for rule, p in r["scan"]["head_paths"]
                if rule == "skills" and "/skills/" in p
            ],
        ),
        ("mcp", lambda r: r["scan"]["snaps"][-1]["mcp"]),
        ("ci agents", lambda r: r["scan"]["snaps"][-1]["ci"]),
        ("reviewers", lambda r: list(r["api"]["reviewers"])),
        ("pr agents", lambda r: list(r["api"]["pr_agents"])),
        ("hook events", lambda r: (r["scan"]["snaps"][-1]["settings"] or {}).get("hooks", [])),
        ("permission mode", lambda r: [(r["scan"]["snaps"][-1]["settings"] or {}).get("mode")]),
    ):
        for lg, repos in leagues.items():
            tally = collections.Counter(x for r in repos for x in set(pick(r)) if x)
            print("top %s (%s, repos):" % (what, lg), tally.most_common(14))


def print_audit(leagues):
    """Example paths behind every rule, to catch rules that match the wrong thing."""
    samples, roots = collections.defaultdict(list), collections.Counter()
    for name, repos in leagues.items():
        for r in repos:
            st = r["scan"]["sets"][r["scan"]["snaps"][-1]["set"]]
            for rule, h in st["hits"].items():
                if h["n"] and rule not in ("workflows", "skill_files"):
                    samples[rule].append("%s: %s" % (r["name"], h["sample"][0]))
            for entry in st["root"]:
                if entry.startswith(".") or entry.isupper() or entry.endswith(".md"):
                    roots[(name, entry)] += 1
    for rule, found in sorted(samples.items()):
        print("\n== %s (%d repos)" % (rule, len(found)))
        for line in found[:10]:
            print("   ", line)
    print("\n== root entries (repos)")
    for league in ("pro", "ladder"):
        top = [(e, c) for (l, e), c in roots.most_common() if l == league and c >= 3]
        print("  ", league, ", ".join("%s %d" % (e, c) for e, c in top[:110]))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--matrix", action="store_true")
    main(ap.parse_args())
