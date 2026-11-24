"""Fingerprints: what a repo's files say about how its team works: its agent setup, its checks, its security, how it
builds and ships. A library of rules that scan.py applies; it is not run on its own.

RULES maps each rule to regexes on repo paths. The part of the path that comes before the fingerprint (`pre`) must not go
through fixtures, templates or examples: those are files a project ships to others, not files it works with. The
rules after RULES are read on file contents: the workflows (what they run, how they hold a coding agent, how they
treat the supply chain), agent hooks and settings, git hooks, package manager files, root instruction files and
commit identities.
"""

import functools
import re

# Path segments that mean "this is shipped or test material, not the team's own setup".
SHIPPED = {
    "node_modules",
    "vendor",
    "vendors",
    "third_party",
    "third-party",
    "testdata",
    "test-data",
    "test",
    "tests",
    "__tests__",
    "e2e",
    "snapshots",
    "__snapshots__",
    "mocks",
    "__mocks__",
    "stubs",
    "dist",
    "build",
    "out",
    "benchmarks",
    "evals",
    "eval",
}
# The same, for words that also show up inside longer names (private-demos, example-apps).
SHIPPED_WORD = re.compile(
    r"(?:^|[-_.])(?:fixtures?|examples?|templates?|samples?|demos?|starters?|quickstarts?"
    r"|boilerplates?|scaffolds?|playgrounds?)(?:$|[-_.])",
    re.I,
)


def anywhere(body, case_sensitive=False):
    return re.compile(r"^(?P<pre>(?:[^/]+/)*?)(?:%s)" % body, 0 if case_sensitive else re.I)


def root_only(body):
    return re.compile(r"^(?P<pre>)(?:%s)" % body, re.I)


def near_root(body):
    """At the root or one or two folders down, where a monorepo keeps a package's own setup."""
    return re.compile(r"^(?P<pre>(?:[^/]+/){0,2})(?:%s)" % body, re.I)


# The agent directories that hold skills, and the ones that hold commands or subagents.
AGENT_DIRS = (
    r"claude|agents?|codex|cursor|github|opencode|gemini|factory|kiro|windsurf|roo|goose|amp|pi"
    r"|kilocode|qoder|trae|junie"
)
COMMAND_DIRS = (
    r"\.claude/commands|\.cursor/commands|\.codex/prompts|\.github/prompts|\.opencode/commands?"
    r"|\.gemini/commands|\.windsurf/workflows|\.factory/commands|\.roo/commands|\.amp/commands"
    r"|\.agents?/commands|\.claude/agents|\.github/agents|\.cursor/agents|\.codex/agents"
    r"|\.opencode/agents?|\.factory/droids|\.gemini/agents|\.kiro/agents|\.agents?/agents"
)
# A skill, command or subagent is sorted by its name: one of these words, whole, between separators.
CHECKS_NAME = (
    r"(?:[^/]*[-_.])?(?:tests?|testing|testers?|e2e|playwright|vitest|jest|pytest|qa|qabot[a-z]*|smoke"
    r"|flak[a-z]*|tdd|coverage|fuzz[a-z]*|verif[a-z]*|regression|acceptance|dogfood|lint(?:ing|er)?"
    r"|fmt|formatting|typecheck|type-check|ci)(?:[-_.][^/]*)?"
)
SECURITY_NAME = (
    r"(?:[^/]*[-_.])?(?:secur(?:e|ity)|vulnerab[a-z]*|cves?|threat[a-z]*|pentest[a-z]*"
    r"|advisor(?:y|ies)(?![-_.]board)|sast|owasp|hardening|dependabot-alerts?|audit-dependencies"
    r"|dependency-audit)(?:[-_.][^/]*)?"
)


RULES = {
    # --- instruction files, one rule per tool family
    "claude_md": [anywhere(r"(?:\.claude/)?CLAUDE\.md$", True), root_only(r"(?:\.claude/)?claude\.md$")],
    "agents_md": [anywhere(r"AGENTS\.md$", True), root_only(r"agents\.md$")],
    "gemini_md": [anywhere(r"GEMINI\.md$", True), root_only(r"gemini\.md$")],
    "cursor_rules": [anywhere(r"\.cursorrules$|\.cursor/rules/.+")],
    "copilot_instructions": [
        anywhere(r"\.github/copilot-instructions\.md$|\.github/instructions/.+\.instructions\.md$")
    ],
    "windsurf_rules": [anywhere(r"\.windsurfrules$|\.windsurf/rules/.+")],
    "cline_roo_rules": [
        anywhere(r"\.clinerules(?:$|/.+)|\.roo/rules[^/]*/.+|\.roorules$|\.roomodes$|\.kilocode/rules/.+")
    ],
    "other_rules": [
        anywhere(
            r"\.junie/guidelines\.md$|\.kiro/steering/.+|\.goosehints$|\.amazonq/rules/.+"
            r"|\.augment/rules/.+|\.augment-guidelines$|\.trae/rules/.+|\.continue/rules/.+"
            r"|\.openhands/microagents/.+|\.aiassistant/rules/.+|\.qoder/rules/.+"
            r"|\.github/chatmodes/.+"
        ),
        root_only(r"(?:\.rules|WARP\.md|CRUSH\.md|QWEN\.md)$"),
    ],
    # --- extensions
    "skills": [
        anywhere(
            r"\.(?:claude|agents?|codex|cursor|github|opencode|gemini|factory|kiro|windsurf|roo|goose"
            r"|amp|pi|kilocode|qoder|trae|junie)/skills?/(?:[^/]+/)+SKILL\.md$"
        )
    ],
    "commands": [
        anywhere(
            r"\.claude/commands/.+\.md$|\.cursor/commands/.+|\.codex/prompts/.+"
            r"|\.github/prompts/.+\.prompt\.md$|\.opencode/commands?/.+|\.gemini/commands/.+"
            r"|\.windsurf/workflows/.+|\.factory/commands/.+|\.roo/commands/.+|\.amp/commands/.+"
            r"|\.agents?/commands/.+"
        )
    ],
    "subagents": [
        anywhere(
            r"\.claude/agents/.+\.md$|\.github/agents/.+\.md$|\.cursor/agents/.+|\.codex/agents/.+"
            r"|\.opencode/agents?/.+|\.factory/droids/.+|\.gemini/agents/.+|\.kiro/agents/.+"
            r"|\.agents?/agents/.+"
        )
    ],
    "mcp_config": [
        anywhere(
            r"\.mcp\.json$|\.cursor/mcp\.json$|\.vscode/mcp\.json$|\.roo/mcp\.json$"
            r"|\.kiro/settings/mcp\.json$|\.amazonq/mcp\.json$|\.windsurf/mcp_config\.json$"
        )
    ],
    "hooks_files": [
        anywhere(
            r"\.claude/hooks/.+|\.cursor/hooks\.json$|\.cursor/hooks/.+|\.github/hooks/.+"
            r"|\.codex/hooks\.json$|\.codex/hooks/.+|\.gemini/hooks/.+|\.kiro/hooks/.+"
            r"|\.windsurf/hooks\.json$|\.factory/hooks/.+"
        )
    ],
    "shared_settings": [
        anywhere(
            r"\.claude/settings\.json$|\.codex/config\.toml$|\.gemini/settings\.json$"
            r"|(?:\.opencode/)?opencode\.jsonc?$|\.cursor/cli\.json$|\.cursor/settings\.json$"
            r"|\.factory/settings\.json$|\.amp/settings\.json$"
        )
    ],
    "plugin_manifest": [anywhere(r"\.(?:claude|cursor|codex)-plugin/(?:plugin|marketplace)\.json$")],
    "agent_ignore": [
        anywhere(
            r"\.(?:cursorignore|cursorindexingignore|claudeignore|aiignore|geminiignore|copilotignore"
            r"|codeiumignore|aiexclude|rooignore|clineignore|kiroignore|aiderignore)$"
        )
    ],
    # --- practices
    # at the root or where a site serves it from, not a reference file inside a skill
    "ai_docs": [
        root_only(r"llms(?:-full|-small|-medium|-ctx)?\.txt$"),
        anywhere(
            r"(?:public|static|docs?|website|www|site|web|content|assets|\.well-known)/"
            r"llms(?:-full|-small|-medium|-ctx)?\.txt$"
        ),
    ],
    "spec_framework": [
        anywhere(
            r"\.specify/.+|\.kiro/specs/.+|openspec/(?:specs|changes)/.+|openspec/(?:project|AGENTS)\.md$"
            r"|\.openspec/.+|\.bmad(?:-core|-method)?/.+|_bmad(?:-output)?/.+|\.agent-os/.+"
            r"|\.planning/.+|\.spec-workflow/.+|\.tessl/.+|specs/\d{3}-[^/]+/(?:spec|plan|tasks)\.md$"
            r"|\.claude/specs/.+|\.ai/specs?/.+"
        )
    ],
    # written plans only: a .gitkeep in .claude/plans says plans are kept out of the repo
    "plans": [
        anywhere(
            r"(?:docs?/)?(?:\.?plans|exec-plans|execplans)/.+\.md$"
            r"|docs/superpowers/(?:plans|specs)/.+\.md$|\.claude/plans/.+\.md$"
            r"|\.cursor/plans/.+\.md$|\.agents?/plans/.+\.md$"
            r"|thoughts/shared/(?:plans|research)/.+\.md$|\.ai/plans/.+\.md$"
            r"|(?:PLAN|EXEC_?PLAN|IMPLEMENTATION_PLAN)\.md$"
        ),
        anywhere(r"PLANS\.md$", True),  # lowercase plans.md is usually a pricing page
    ],
    "task_tracker": [
        anywhere(
            r"\.beads/.+|\.taskmaster/.+|\.task-master/.+|backlog/tasks/.+\.md$|\.backlog/.+"
            r"|\.agents?/tasks/.+|\.claude/tasks/.+|\.ai/tasks/.+"
        )
    ],
    "memory": [
        anywhere(
            r"memory-bank/.+|\.serena/.+|\.claude/memory/.+|\.cursor/memor(?:y|ies)/.+"
            r"|\.agents?/memory/.+|\.ai/memory/.+|\.letta/.+|\.claude/agent-memory/.+|\.mem0/.+"
        ),
        root_only(r"MEMORY\.md$"),
    ],
    "adr": [
        anywhere(
            r"(?:docs?/)?(?:adrs?|decisions|architecture/decisions|architecture-decisions"
            r"|architecture/adrs?)/.+\.md$"
        )
    ],
    "parallel_setup": [
        anywhere(
            r"\.cursor/worktrees\.json$|\.worktreeinclude$|conductor\.json$|\.conductor/.+"
            r"|\.superset/.+|\.sculptor/.+|\.crystal/.+|\.vibe-kanban/.+"
        )
    ],
    "cloud_agent_env": [
        anywhere(
            r"\.github/workflows/copilot-setup-steps\.ya?ml$|\.cursor/environment\.json$"
            r"|\.cursor/Dockerfile$|\.codex/(?:setup|environment)[^/]*$|\.codex/environments/.+"
            r"|\.devin/.+|\.openhands/(?:setup|pre-commit)\.sh$"
        )
    ],
    "ai_review_config": [
        anywhere(
            r"\.coderabbit\.ya?ml$|\.cursor/BUGBOT\.md$|BUGBOT\.md$|greptile\.json$"
            r"|\.greptile/.+|\.pr_agent\.toml$|\.qodo/.+|\.sourcery\.ya?ml$|\.ellipsis/.+"
            r"|ellipsis\.ya?ml$|\.github/copilot-review-instructions\.md$|\.macroscope/.+"
            r"|cubic\.ya?ml$|\.cubic/.+|\.bito/.+|\.korbit/.+"
            r"|\.claude/commands/[^/]*review[^/]*\.md$"
        ),
        root_only(r"REVIEW\.md$"),
    ],
    "rules_sync_tool": [
        anywhere(r"\.rulesync/.+|rulesync\.jsonc?$|\.ruler/.+|ai-rulez\.ya?ml$|\.ai-rulez/.+|\.agentrules$")
    ],
    "ai_policy": [
        anywhere(
            r"(?:\.github/)?(?:AI[_-]POLICY|AI[_-]USAGE(?:[_-]POLICY)?|AI[_-]CONTRIBUTIONS?"
            r"|AI[_-]GUIDELINES|AI[_-]DISCLOSURE)\.md$"
        )
    ],
    # --- checks: the linters, formatters, hooks and test tools a repo configures. Most are older
    # than agents: they are read to see what changed around them, not as agent practices.
    "oxlint": [anywhere(r"\.oxlintrc\.jsonc?$|oxlint\.config\.[cm]?[jt]s$")],
    "oxfmt": [anywhere(r"\.oxfmtrc\.jsonc?$|oxfmt\.config\.[cm]?[jt]s$")],
    "biome": [anywhere(r"biome\.jsonc?$")],
    "eslint": [anywhere(r"\.eslintrc(?:\.[a-z]+)?$|eslint\.config\.[cm]?[jt]s$")],
    "prettier": [anywhere(r"\.prettierrc(?:\.[a-z0-9]+)?$|prettier\.config\.[cm]?[jt]s$")],
    "knip": [anywhere(r"\.?knip\.(?:jsonc?|[cm]?[jt]s)$|knip\.config\.(?:[cm]?[jt]s|jsonc?)$")],
    "import_rules": [
        anywhere(r"\.?dependency-cruiser(?:\.config)?\.(?:[cm]?js|json)$|\.madgerc$|tach\.toml$|\.importlinter$")
    ],
    # Lint rules written in the repo itself, on top of a linter's own: the rule files of a local plugin
    # or of a rules folder. A plugin released as a package is taken out by the scan (PLUGIN_RELEASED).
    "custom_lint": [
        anywhere(
            r"[^/]+\.grit$|biome-plugins/.+\.grit$|\.grit/.+\.(?:grit|md|ya?ml)$"
            r"|(?:oxlint-plugins?(?:-[^/]+)?|\.oxlint|oxlint/(?:rules|plugins?)|eslint-rules?|eslint-local-rules"
            r"|eslint-plugin(?:-[^/]+)?|eslint/(?:rules|plugins?)|\.eslint|eslint-custom[^/]*"
            r"|(?:pylint|flake8)[-_]plugins?|lint-rules|custom-lints?)/.+\.(?:[cm]?[jt]sx?|py|ya?ml|go|grit)$"
            r"|eslint-local-rules\.[cm]?[jt]s$|sgconfig\.ya?ml$|\.?ast-grep/.+\.ya?ml$"
            r"|\.semgrep/.+\.ya?ml$|\.semgrep\.ya?ml$|semgrep(?:-rules)?/[^/]+\.ya?ml$"
            r"|\.golangci/rules\.go$|ruleguard[^/]*\.go$|gorules/.+\.go$"
        )
    ],
    "git_hooks": [
        anywhere(
            r"(?:\.husky|\.vite-hooks|\.?git-?hooks|hooks)/(?:pre-commit|pre-push|commit-msg|prepare-commit-msg"
            r"|post-merge|post-checkout|post-commit|pre-rebase)(?:\.sh)?$"
            r"|\.?lefthook(?:-local)?\.(?:ya?ml|toml|json)$|\.pre-commit-config\.ya?ml$|prek\.toml$"
        )
    ],
    "lint_staged": [anywhere(r"\.lintstagedrc(?:\.[a-z]+)?$|lint-staged\.config\.[cm]?[jt]s$")],
    "vitest": [anywhere(r"vitest\.(?:[\w-]+\.)?(?:config|workspace)\.[cm]?[jt]s$|vitest\.config\.[\w-]+\.[cm]?[jt]s$")],
    "jest": [anywhere(r"jest\.config\.(?:[cm]?[jt]s|json)$")],
    "playwright": [anywhere(r"playwright(?:-ct)?\.config\.[cm]?[jt]s$")],
    "cypress": [anywhere(r"cypress\.config\.[cm]?[jt]s$|cypress\.json$")],
    "pytest": [anywhere(r"pytest\.ini$|conftest\.py$")],
    "mutation_tests": [
        anywhere(
            r"(?:[\w-]+\.)?stryker\.conf(?:ig)?\.(?:[cm]?js|json)$|(?:\.cargo/)?mutants\.toml$|infection\.json(?:\.dist|5)?$"
        )
    ],
    # a skill, a command or a subagent named for tests, lint, types or CI
    "checks_ext": [
        anywhere(
            r"\.(?:%s)/skills?/(?:[^/]+/)*?%s/SKILL\.md$|(?:%s)/(?:[^/]+/)*?%s$"
            % (AGENT_DIRS, CHECKS_NAME, COMMAND_DIRS, CHECKS_NAME)
        )
    ],
    # --- security: of the code, of its supply chain and of the agent
    "security_md": [root_only(r"(?:\.github/|docs?/)?SECURITY\.(?:md|rst|txt)$")],
    "dependabot": [root_only(r"\.github/dependabot\.ya?ml$")],
    "renovate": [
        root_only(
            r"(?:\.github/|\.gitlab/)?\.?renovate(?:rc)?(?:\.json5?)?$"
            r"|\.github/renovate[^/]*\.json5?$|renovate\.config\.[cm]?js$"
        )
    ],
    "codeowners": [root_only(r"(?:\.github/|docs/)?CODEOWNERS$")],
    "zizmor": [root_only(r"(?:\.github/)?\.?zizmor\.ya?ml$")],
    "secret_scan": [
        root_only(
            r"(?:\.github/)?\.?gitleaks(?:ignore|\.toml)$|\.gitleaks/.+|\.secrets\.baseline$|\.gitguardian(?:\.ya?ml)?$"
            r"|\.trufflehog[^/]*$|\.secretlintrc(?:\.[a-z]+)?$"
        )
    ],
    "dep_audit": [
        root_only(
            r"socket\.ya?ml$|\.snyk$|(?:\.github/)?osv-scanner\.toml$|\.trivyignore(?:\.ya?ml)?$|trivy\.ya?ml$"
            r"|audit-ci\.jsonc?$|\.grype\.ya?ml$|\.nsprc$"
        ),
        anywhere(r"deny\.toml$|\.cargo/audit\.toml$"),
    ],
    "threat_model": [anywhere(r"[^/]*threat[-_]?model[^/]*\.md$")],
    "oss_scanner": [root_only(r"(?:\.github/)?\.?oss-scanner/.+")],
    # fuzz tests: code in a fuzz folder, a fuzz target named so, or a ClusterFuzzLite setup. Not the docs or the
    # inputs a fuzzer keeps (a corpus, crash files): only code files and a fuzz crate's Cargo.toml
    "fuzz_tests": [
        anywhere(
            r"(?:fuzz|fuzzing|fuzzers?|fuzz[-_]targets?)/(?:[^/]+/)*[^/]+\.(?:rs|go|c|cc|cpp|cxx|h|py|java|kt|js|ts|swift|zig)$"
            r"|(?:fuzz|fuzzing)/Cargo\.toml$|\.clusterfuzzlite/.+"
            r"|[^/]*[-_]fuzz(?:er|ing)?(?:[-_]test)?\.(?:rs|go|c|cc|cpp|py)$|fuzz_[^/]+\.(?:rs|go|c|cc|cpp|py)$"
        )
    ],
    # permission or sandbox files of an agent other than Claude Code, whose rules sit in its settings
    "agent_permissions": [
        anywhere(r"\.cursor/(?:cli|sandbox)\.json$|\.codex/rules/.+\.rules$|\.gemini/policies/.+\.toml$")
    ],
    "devcontainer": [root_only(r"\.devcontainer/(?:[^/]+/)?devcontainer\.json$|\.devcontainer\.json$")],
    # a skill, a command or a subagent named for security
    "security_ext": [
        anywhere(
            r"\.(?:%s)/skills?/(?:[^/]+/)*?%s/SKILL\.md$|(?:%s)/(?:[^/]+/)*?%s$"
            % (AGENT_DIRS, SECURITY_NAME, COMMAND_DIRS, SECURITY_NAME)
        )
    ],
    # --- read for their content, not counted as a fingerprint by themselves
    "workflows": [root_only(r"\.github/workflows/[^/]+\.(?:ya?ml|md)$")],
    # every SKILL.md under a skills/ directory: counted only when an agent directory links to it
    "skill_files": [anywhere(r"skills?/(?:[^/]+/)+SKILL\.md$")],
    # the package manager's files at the root: tools installed, release cooldowns
    "pkg_files": [
        root_only(
            r"(?:package\.json|pnpm-workspace\.yaml|\.npmrc|\.yarnrc\.yml|bunfig\.toml"
            r"|pyproject\.toml|uv\.toml)$"
        )
    ],
    # the same settings files one or two folders down, where a monorepo keeps a package manager of its own
    "pkg_nested": [
        re.compile(
            r"^(?P<pre>(?:[^/]+/){1,2})(?:pnpm-workspace\.yaml|\.npmrc|\.yarnrc\.yml|bunfig\.toml"
            r"|uv\.toml)$",
            re.I,
        )
    ],
    # --- the practices added in Issue #1, the page's first issue: build, test and ship. Wide on purpose: the scan keeps
    # the paths, so a rule is tightened later with no new reading; a doubtful trace has a rule of its own.
    # Build
    "issue_templates": [root_only(r"(?:\.github/|docs/)?(?:ISSUE_TEMPLATE/.+|ISSUE_TEMPLATE\.md$)")],
    "pr_template": [
        root_only(r"(?:\.github/|docs/)?(?:pull_request_template(?:\.(?:md|txt))?$|PULL_REQUEST_TEMPLATE/.+)")
    ],
    "toolchain_files": [
        root_only(
            r"(?:\.nvmrc|\.node-version|\.python-version|\.ruby-version|rust-toolchain(?:\.toml)?|\.tool-versions"
            r"|\.?mise\.toml|\.mise/config\.toml|\.config/mise\.toml|\.config/mise/config\.toml|mise/config\.toml)$"
        )
    ],
    # the version files of other languages and tools: not in the method's list, kept apart
    "toolchain_other": [
        root_only(r"(?:\.go-version|\.java-version|\.bun-version|\.terraform-version|\.sdkmanrc|\.prototools)$")
    ],
    "compose": [near_root(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$")],
    "task_runner": [root_only(r"(?:makefile|gnumakefile|\.?justfile|taskfile(?:\.dist)?\.ya?ml)$")],
    "editorconfig": [root_only(r"\.editorconfig$")],
    "editor_settings": [root_only(r"(?:\.vscode/(?:settings|extensions)\.json|\.zed/settings\.json)$")],
    # other files of an editor's shared setup: launch and task configs, a workspace file. A bare .idea/ is not read
    "editor_other": [root_only(r"(?:\.vscode/(?:launch|tasks)\.json|[^/]+\.code-workspace|\.zed/tasks\.json)$")],
    "env_example": [
        near_root(
            r"(?:\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist|tmpl|tpl)|\.env\.(?:example|sample|template)\.[\w-]+"
            r"|(?:[\w-]+\.)?(?:example|sample)\.env|env\.(?:example|sample|template))$"
        )
    ],
    "stale_config": [root_only(r"\.github/stale\.ya?ml$")],
    "nix_env": [root_only(r"(?:flake\.nix|shell\.nix|devbox\.json|devenv\.nix)$")],
    "patches": [root_only(r"(?:patches|\.yarn/patches)/.+\.(?:patch|diff)$")],
    "labeler_config": [root_only(r"\.github/labeler\.ya?ml$")],
    # Test
    "formatter_config": [
        near_root(
            r"\.prettierrc(?:\.[a-z0-9]+)?$|prettier\.config\.[cm]?[jt]s$|biome\.jsonc?$|\.oxfmtrc\.jsonc?$"
            r"|oxfmt\.config\.[cm]?[jt]s$|\.?rustfmt\.toml$|[._]clang-format$|\.?dprint\.jsonc?$|\.dprintrc\.json$"
            r"|\.?taplo\.toml$|\.?stylua\.toml$|\.swiftformat$|\.swift-format$|\.formatter\.exs$"
        )
    ],
    # formatters the method does not name: Scala, OCaml, PHP CS Fixer, Clojure, treefmt, yamlfmt, CMake
    "formatter_other": [
        near_root(
            r"\.scalafmt\.conf$|\.ocamlformat$|\.php-cs-fixer(?:\.dist)?\.php$|\.cljfmt\.edn$|\.?treefmt\.toml$"
            r"|\.?yamlfmt(?:\.ya?ml)?$|\.gersemirc$|\.cmake-format(?:\.ya?ml|\.py|\.json)?$"
        )
    ],
    "coverage_config": [
        near_root(r"\.?codecov\.ya?ml$|\.coveragerc$|\.nycrc(?:\.[a-z]+)?$|\.c8rc(?:\.[a-z]+)?$|\.?coveralls\.ya?ml$")
    ],
    # coverage configs of other tools: SimpleCov, tarpaulin
    "coverage_other": [near_root(r"\.simplecov$|\.?tarpaulin\.toml$")],
    "spellcheck_config": [
        near_root(r"[._]?typos\.toml$|\.?cspell\.jsonc?$|cspell\.config\.[a-z]+$|\.?cspell\.ya?ml$|\.codespellrc$")
    ],
    "actionlint_config": [root_only(r"\.github/actionlint\.ya?ml$")],
    # Ship
    "changelog": [
        root_only(r"(?:changelog|changes|history|news|releases|release[-_]?notes)(?:\.(?:md|rst|txt|markdown|adoc))?$")
    ],
    # a folder of one note per change (towncrier, changie, scriv and the like), gathered into the changelog at a release. A
    # changelog split by version is not one (NOT_THIS)
    "changelog_dir": [root_only(r"(?:changelogs?|\.changes|\.changelog|changelog\.d|changes\.d|newsfragments)/.+")],
    "docs_site": [
        near_root(
            r"mint\.json$|docusaurus\.config\.[cm]?[jt]s$|mkdocs\.ya?ml$|\.readthedocs\.ya?ml$|readthedocs\.ya?ml$"
            r"|(?:docs?|documentation|sphinx)/(?:source/)?conf\.py$|\.vitepress/config\.[cm]?[jt]s$"
            r"|typedoc\.jsonc?$|typedoc\.config\.[cm]?[jt]s$|book\.toml$"
        )
    ],
    # Mintlify's newer docs.json: a name that other files take, so kept apart, and only in a docs folder or at the root
    "docs_json": [root_only(r"docs\.json$"), near_root(r"(?:docs?|documentation)/docs\.json$")],
    # docs tools the method does not name: Antora, DocFX, Doxygen, Rspress, VuePress, Jupyter Book, Zensical
    "docs_other": [
        near_root(
            r"antora(?:-playbook)?\.ya?ml$|docfx\.json$|doxyfile$|rspress\.config\.[cm]?[jt]s$"
            r"|\.vuepress/config\.[cm]?[jt]s$|_toc\.ya?ml$|zensical\.toml$"
        )
    ],
    # commitlint's config: a check of the convention. A commitizen config alone (.cz.toml, .czrc) helps write a commit and
    # checks nothing, so it is not counted
    "commit_convention": [near_root(r"commitlint\.config\.[a-z]+$|\.commitlintrc(?:\.[a-z]+)?$")],
    "changesets": [root_only(r"\.changeset/config\.json$")],
    "lint_staged_config": [anywhere(r"\.lintstagedrc(?:\.[a-z]+)?$|lint-staged\.config\.[a-z]+$")],
}
# The rules of Issue #1 above. Their paths come after the others in a scan's head_paths, so its cap never takes away a
# path of the other rules, whose figures were already published.
ISSUE1_RULES = {
    "issue_templates",
    "pr_template",
    "toolchain_files",
    "toolchain_other",
    "compose",
    "task_runner",
    "editorconfig",
    "editor_settings",
    "editor_other",
    "env_example",
    "stale_config",
    "nix_env",
    "patches",
    "labeler_config",
    "formatter_config",
    "formatter_other",
    "coverage_config",
    "coverage_other",
    "spellcheck_config",
    "actionlint_config",
    "changelog",
    "changelog_dir",
    "docs_site",
    "docs_json",
    "docs_other",
    "commit_convention",
    "changesets",
    "lint_staged_config",
}

# Rules about the checks a repo runs. A test folder is where some of these files live (a runner's
# config, an end-to-end suite's hooks), so for them only vendored and shipped material is left out.
IN_TESTS = {"vitest", "jest", "playwright", "cypress", "pytest", "mutation_tests", "fuzz_tests"}
TEST_DIRS = {"test", "tests", "__tests__", "e2e"}
# The rules of the checks and of security. For them a few more folders are shipped: an app built to
# test the product, a benchmark, a sandbox. The agent practices do not leave these out: their published figures were
# counted with them.
LENS_RULES = {
    "oxlint",
    "oxfmt",
    "biome",
    "eslint",
    "prettier",
    "knip",
    "import_rules",
    "custom_lint",
    "git_hooks",
    "lint_staged",
    "vitest",
    "jest",
    "playwright",
    "cypress",
    "pytest",
    "mutation_tests",
    "checks_ext",
    "security_md",
    "dependabot",
    "renovate",
    "codeowners",
    "zizmor",
    "secret_scan",
    "dep_audit",
    "threat_model",
    "oss_scanner",
    "agent_permissions",
    "devcontainer",
    "security_ext",
    "pkg_files",
    "pkg_nested",
    "fuzz_tests",
}
LENS_SHIPPED = {
    "bench",
    "test-applications",
    "test-application",
    "test-apps",
    "test-app",
    "__testfixtures__",
    "sandbox",
    "sandboxes",
}
# Rules whose every folder is tested, down to the file's own: fixtures and snapshots sit inside a rules folder.
WHOLE_PATH = {"custom_lint"}
# A lint plugin released as a package (it has a changelog, a licence or an .npmignore at its root) is
# written for the product's users: its folder, and the file that gives it away.
PLUGIN_RELEASED = re.compile(
    r"^((?:[^/]+/)*?(?:eslint|oxlint|biome)-plugins?(?:-[^/]+)?/)(?:changelog[^/]*|license[^/]*|\.npmignore)$", re.I
)

# An agent directory that is a symlink or a submodule, e.g. .claude/skills -> ../skills.
LINKED_DIR = re.compile(
    r"^(?P<pre>(?:[^/]+/)*?)\.(?P<tool>claude|agents?|codex|cursor|github|opencode|gemini|factory"
    r"|kiro|windsurf|roo|amp)/(?P<kind>skills?|commands?|prompts|agents|hooks|rules)$",
    re.I,
)
LINKED_KIND = {
    "skill": "skills",
    "skills": "skills",
    "command": "commands",
    "commands": "commands",
    "prompts": "commands",
    "agents": "subagents",
    "hooks": "hooks_files",
}
LINKED_RULES = {"cursor": "cursor_rules", "windsurf": "windsurf_rules"}


def is_shipped(pre, in_tests=False, lens=False):
    """Whether the folders before a fingerprint mark it as shipped. `in_tests` lets test folders
    through; `lens` adds the folders that are shipped for the checks and security rules only."""
    return any(
        (seg.lower() in SHIPPED and not (in_tests and seg.lower() in TEST_DIRS))
        or (lens and seg.lower() in LENS_SHIPPED)
        or SHIPPED_WORD.search(seg)
        for seg in pre.split("/")
        if seg
    )


def match_link(path):
    """Same as match(), for a path that is a symlink or a submodule."""
    m = LINKED_DIR.match(path)
    if not m:
        return None
    rule = LINKED_KIND.get(m.group("kind").lower()) or LINKED_RULES.get(m.group("tool").lower(), "other_rules")
    return rule, is_shipped(m.group("pre")), m.group("pre") == ""


INSTRUCTION_RULES = [
    "claude_md",
    "agents_md",
    "gemini_md",
    "cursor_rules",
    "copilot_instructions",
    "windsurf_rules",
    "cline_roo_rules",
    "other_rules",
]

# Cheap test run on every path before the rules; anything a rule can match must pass it.
PREFILTER = re.compile(
    r"claude|agents?\.md|agents?/|gemini|\.cursor|copilot|\.windsurf|\.cline|\.roo|\.kilo|\.kiro"
    r"|\.junie|\.goose|\.amazonq|\.augment|\.trae|\.continue|\.openhands|\.aiassistant|\.qoder"
    r"|\.rules$|warp\.md|crush\.md|qwen\.md|chatmodes|skill\.md|\.codex|opencode|\.factory|\.amp/"
    r"|\.pi/|mcp|hooks|plugin/|ignore$|\.aiexclude|llms|\.specify|openspec|bmad|\.agent-os"
    r"|\.planning|\.spec-workflow|\.tessl|specs/\d{3}-|\.ai/|plans?/|plans?\.md|plan\.md"
    r"|superpowers|thoughts/shared|\.beads|task-?master|backlog|memory|\.serena|\.letta|\.mem0"
    r"|adrs?/|decisions/|worktree|conductor|\.superset|\.sculptor|\.crystal|\.vibe-kanban"
    r"|environment|\.jules|\.devin|coderabbit|bugbot|greptile|pr_agent|\.qodo|sourcery|ellipsis"
    r"|review|macroscope|cubic|\.bito|\.korbit|rulesync|\.ruler|ai-rulez|agentrules"
    r"|ai[_-](?:policy|usage|contrib|guide|disclos)|\.github/(?:workflows|instructions|prompts)/"
    # checks and security
    r"|oxlint|oxfmt|biome|eslint|prettier|knip|dependency-cruiser|madgerc|tach\.toml|importlinter|\.grit"
    r"|sgconfig|ast-grep|semgrep|golangci|ruleguard|gorules|clj-kondo|pylint|flake8|lint-rules|custom-lint"
    r"|\.husky|lefthook|pre-commit-config|\.githooks|prek\.toml|lint-?staged|vitest|jest\.config|playwright"
    r"|cypress\.|pytest\.ini|conftest\.py|stryker|mutants\.toml|infection\.json|security\.(?:md|rst|txt)|dependabot"
    r"|renovate|codeowners|zizmor|gitleaks|secrets\.baseline|gitguardian|trufflehog|secretlint|socket\.ya?ml"
    r"|\.snyk|osv-scanner|trivy|audit-ci|\.grype|\.nsprc|deny\.toml|audit\.toml|threat|oss-scanner|\.rules$"
    r"|policies/|devcontainer|fuzz|^(?:package\.json|pyproject\.toml)$"
    r"|(?:^|/)(?:pnpm-workspace\.yaml|\.npmrc|\.yarnrc\.yml|bunfig\.toml|uv\.toml)$"
    # the practices of Issue #1
    r"|issue_template|pull_request_template|-version$|\.nvmrc|tool-versions|rust-toolchain|\.sdkmanrc|\.prototools|mise|compose"
    r"|makefile|justfile|taskfile|editorconfig|\.vscode/|\.zed/|code-workspace|env\.|\.env|stale\.ya?ml|\.nix$"
    r"|devbox|patches/|labeler|formatter|rustfmt|clang-format|dprint|taplo|stylua|swift-?format|scalafmt"
    r"|ocamlformat|php-cs-fixer|cljfmt|treefmt|yamlfmt|gersemi|cmake-format|codecov|coveragerc|nycrc|c8rc"
    r"|coveralls|simplecov|tarpaulin|typos|cspell|codespell|actionlint|^(?:changelog|changes|history|news|release)"
    r"|^\.changes/|^\.changelog/|newsfragments|mint\.json|docs\.json|docusaurus|mkdocs|conf\.py$|readthedocs"
    r"|vitepress|vuepress|typedoc|book\.toml|antora|docfx|doxyfile|rspress|_toc\.ya?ml|zensical|commitlint"
    r"|cz\.|czrc|\.changeset/",
    re.I,
)


# Paths a rule would match that are not the practice it stands for.
NOT_THIS = {
    # a plan.md that documents a skill or is a slash command, not a plan someone wrote
    "plans": re.compile(r"(?:^|/)(?:skills?|references|commands)/", re.I),
    # an MCP config shipped inside the product's own plugin for an agent
    "mcp_config": re.compile(r"(?:^|/)(?:plugins?|integrations?|providers)/", re.I),
    # the changelog or the docs of a lint plugin, not its rules
    "custom_lint": re.compile(r"(?:^|/)(?:changelogs?|docs?|website)/", re.I),
    # a script of that name among an agent's hooks is not a git hook
    "git_hooks": re.compile(r"(?:^|/)\.(?:%s)/" % AGENT_DIRS, re.I),
    # docs/security.md in lower case is a page of the product's docs, not the policy GitHub reads
    "security_md": re.compile(r"^docs?/security\.md$"),
    # the rules of Issue #1, tightened on what the scans found. A workflow named for Compose is not a Compose file
    "compose": re.compile(r"(?:^|/)\.github/workflows/", re.I),
    # the coverage config of a vendored copy of another project
    "coverage_config": re.compile(r"(?:^|/)vendored/", re.I),
    # a changelog split by version (changelog/v1.2.md, CHANGELOG/26.10.md, changelogs/CHANGELOG.0.10.md) or a page about it,
    # not a note per change
    "changelog_dir": re.compile(
        r"^changelogs?/(?:changelog[^/]*|readme[^/]*|index\.html?|v?\d+(?:[.-]v?\d+)*(?:\.\w+)?)$", re.I
    ),
}
# Rules whose file names often name a person (a change note named for its author's account, a patch of a package kept on a
# person's scope): the scan counts their paths and keeps none of them, in a sample or in head_paths, so that the stored data
# names no one. Such a rule is tightened by the next scan, not on stored paths.
UNSTORED = {"changelog_dir", "patches"}


def match(path):
    """Yield (rule_id, shipped, at_root) for every rule the path satisfies."""
    if not PREFILTER.search(path):
        return
    for rule_id, patterns in RULES.items():
        if rule_id in NOT_THIS and NOT_THIS[rule_id].search(path):
            continue
        for pattern in patterns:
            m = pattern.match(path)
            if m:
                folders = path.rpartition("/")[0] if rule_id in WHOLE_PATH else m.group("pre")
                yield rule_id, is_shipped(folders, rule_id in IN_TESTS, rule_id in LENS_RULES), m.group("pre") == ""
                break


# --- content rules --------------------------------------------------------------------

# A coding agent invoked from a GitHub Actions workflow (text is lowercased first).
CI_AGENTS = {
    "claude": r"anthropics/claude-code-(?:base-)?action|anthropics/claude-code-security-review"
    r"|@anthropic-ai/claude-code|claude\.ai/install\.sh|\bclaude\s+(?:-p\b|--print\b)"
    r"|claude_code_oauth_token",
    "codex": r"openai/codex-action|@openai/codex\b|\bcodex\s+exec\b",
    "gemini": r"google-github-actions/run-gemini-cli|@google/gemini-cli"
    r"|\bgemini\s+(?:-p\b|--prompt\b|--yolo\b)",
    "copilot": r"github/gh-aw|githubnext/gh-aw|@github/copilot\b|\bcopilot\s+(?:-p\b|--prompt\b)",
    "cursor": r"cursor-agent\b|cursor\.com/install",
    "opencode": r"(?:sst|anomalyco)/opencode/github|\bopencode\s+(?:run|github)\b|opencode\.ai/install",
    "amp": r"@sourcegraph/amp\b|ampcode\.com/install|\bamp\s+(?:-x\b|--execute\b)",
    "aider": r"\baider-chat\b|\baider\s+--",
    "openhands": r"all-hands-ai/openhands|openhands/openhands|openhands-resolver",
    "droid": r"factory-ai/droid|\bdroid\s+exec\b",
    "goose": r"block/goose|\bgoose\s+run\b",
    "warp": r"warpdotdev/[a-z-]*agent[a-z-]*action|oz-agent",
    "devin": r"api\.devin\.ai",
    "jules": r"google-labs-code/jules|jules-action",
}
CI_AGENTS = {k: re.compile(v) for k, v in CI_AGENTS.items()}
# Weaker signal: a model API key in CI. Often product tests or evals, so reported apart.
CI_LLM_KEY = re.compile(
    r"anthropic_api_key|openai_api_key|gemini_api_key|openrouter_api_key"
    r"|ai_gateway_api_key"
)

# --- checks and security, read from file contents ---------------------------------------
# Every text is lowercased before it is matched, except instruction files (see INSTRUCTIONS_SAY).

# What a CI workflow runs. Tests and linters are older than agents and near-universal among the
# pros: these three are a floor to compare with, not practices. They are matched on what a workflow
# runs (scan.workflow_commands: the actions it uses, its run blocks, the root package.json scripts
# those call), not on step names, path filters or an agent's prompt.
# A package manager and what may stand between it and the script it runs: `pnpm --filter x test`, `yarn workspace x lint`.
PACKAGE_MANAGER_RUN = (
    r"(?:pnpm|npm|yarn|bun)(?:\s+(?:run|exec|-w|-r|--recursive|--workspaces|--if-present|-f\s*\S+"
    r"|--filter[= ]\S+|workspace\s+\S+|(?:-c|--cwd|--dir|--prefix)[= ]\S+))*"
)
# A make or just target: lint, lint_package, test-unit. Its words are split by - or _, so a word
# holds neither (with \w, which takes the underscore, a long name could be split in too many ways).
TARGET = lambda words: r"(?:[a-z0-9]+[-_])*(?:%s)(?:[-_][a-z0-9]+)*" % words
# The name of a package script, its parts split by : or -: lint, check:lint, lint-fix, test:unit.
SCRIPT = lambda words: r"(?:[\w.]+[:-])*(?:%s)(?:[:-][\w.]+)*" % words
SCRIPT_TESTS = SCRIPT(r"tests?(?!:types?\b)|coverage|e2e")  # `test:types` is a type check
SCRIPT_LINT = SCRIPT("lint|format|fmt")
# A turbo task among several: `turbo run lint test`.
TURBO = lambda words: r"turbo (?:run )?(?:[\w:=-]+ )*?[\w:-]*(?:%s)[\w:-]*" % words
CI_CHECKS = {
    "tests": r"\b(?:pytest|jest|vitest|mocha|go test|cargo (?:nextest|test)|bun test|playwright test|cypress run|mix test"
    r"|rspec|rake (?:test|spec)|dotnet test|deno test|swift test|flutter test|sbt test|bazel(?:isk)? test"
    r"|phpunit|ctest|nox|tox|%s\s+%s|make %s|just %s|mise run [\w:-]*test[\w:-]*"
    r"|%s|nx (?:run-many|affected|run|test)\b[^\n]*test"
    r"|gradlew? [^\n]*(?:test|check)|mvnw? [^\n]*(?:test|verify))\b"
    % (PACKAGE_MANAGER_RUN, SCRIPT_TESTS, TARGET("tests?"), TARGET("tests?"), TURBO("test")),
    "lint": r"\b(?:eslint|oxlint|biome (?:ci|check|lint|format)|ruff(?:-action| check| format)|golangci-lint|clippy"
    r"|rubocop|standardrb|prettier|oxfmt|dprint|gofmt|gofumpt|cargo fmt|rustfmt|pre-commit|prek|lefthook run"
    r"|ktlint|detekt|swiftlint|swiftformat|shellcheck|flake8|pylint|black|isort|stylelint|hadolint|buf lint"
    r"|mix (?:format|credo)|super-linter|ultracite|%s\s+%s|make %s|just %s"
    r"|mise run [\w:-]*(?:lint|fmt|format)[\w:-]*|%s"
    # the word alone, as a task or a script a command names: `clojure -M:lint`, `deno task lint`, `tools/lint.js`
    r"|nx (?:run-many|affected)\b[^\n]*lint|(?<![\w-])lint)\b"
    % (
        PACKAGE_MANAGER_RUN,
        SCRIPT_LINT,
        TARGET("lint|fmt|format"),
        TARGET("lint|fmt|format"),
        TURBO("lint|fmt|format"),
    ),
    "types": r"\b(?:tsc|tsgo|vue-tsc|typecheck|type-check|check-types|types?:check|check:types|test:types"
    r"|typescript:check|mypy|pyright|basedpyright|ty check|pyrefly|cargo check|go vet|flow check|sorbet"
    r"|steep check|phpstan|psalm)\b",
}
CI_CHECKS = {k: re.compile(v) for k, v in CI_CHECKS.items()}
# A script of the root package.json called from a workflow: its body is read as part of what the workflow runs.
SCRIPT_CALL = re.compile(r"\b(?:pnpm|npm|yarn|bun)(?:\s+(?:run|-w|-r|--recursive|--if-present))*\s+([\w:.-]+)")

# Security tools a workflow calls.
CI_SCANNERS = {
    "codeql": r"github/codeql-action/(?:init|analyze)",  # upload-sarif alone sends another tool's results
    "semgrep": r"semgrep",
    "sonar": r"sonarsource/|sonarcloud|sonarqube|sonar-scanner",
    "snyk": r"snyk/actions|\bsnyk (?:test|code|monitor)\b",
    "code_lint": r"\bbandit\b|\bgosec\b|\bbrakeman\b",
    "trivy": r"aquasecurity/trivy|\btrivy (?:fs|image|config|repo)\b",
    "grype": r"anchore/scan-action|\bgrype\b",
    "osv": r"osv-scanner",
    "govulncheck": r"govulncheck",
    "cargo_audit": r"cargo[- ]audit\b|cargo[- ]deny\b|rustsec/audit-check|embarkstudios/cargo-deny-action",
    "pip_audit": r"pip-audit|\bsafety (?:check|scan)\b",
    "npm_audit": r"\b(?:npm|pnpm|yarn|bun) audit\b|audit-ci",
    "dependency_review": r"actions/dependency-review-action",
    "socket": r"socketdev/|@socketsecurity/",
    "gitleaks": r"gitleaks",
    "trufflehog": r"trufflehog",
    "gitguardian": r"gitguardian|ggshield",
    "scorecard": r"ossf/scorecard-action",
    "zizmor": r"\bzizmor\b",
    "actionlint": r"actionlint",
    "harden_runner": r"step-security/harden-runner",
}
CI_SCANNERS = {k: re.compile(v) for k, v in CI_SCANNERS.items()}
# The job each one does: reads the code, audits the dependencies, looks for secrets, lints the workflows.
SCANNER_JOBS = {
    "code": ("codeql", "semgrep", "sonar", "snyk", "code_lint"),
    "deps": (
        "trivy",
        "grype",
        "osv",
        "govulncheck",
        "cargo_audit",
        "pip_audit",
        "npm_audit",
        "dependency_review",
        "socket",
        "snyk",
    ),
    "secrets": ("gitleaks", "trufflehog", "gitguardian"),
    "workflows": ("zizmor", "actionlint"),
}

# Security as a whole, beyond the scanners above: what a workflow does to the supply chain and the code it ships.
# Matched, as CI_SCANNERS are, on what a workflow runs (scan.workflow_commands): the actions it uses, its run blocks, the
# root package.json scripts they call.
CI_SUPPLY = {
    # what it builds is signed or attested: GitHub's attestations, SLSA, cosign, npm's provenance (not --provenance=false)
    "provenance": r"actions/attest(?:-build-provenance)?@|slsa-framework/slsa-github-generator|\bcosign\s+(?:sign|attest)"
    r"(?:-blob)?\b|--provenance\b(?![= \t]*false)",
    # a software bill of materials: syft, CycloneDX, an SPDX file, buildx's --sbom (not --sbom=false)
    "sbom": r"anchore/sbom-action|actions/attest-sbom|\bsyft\b|cyclonedx|--sbom\b(?![= \t]*false)|\btype=sbom\b"
    r"|\bsbom-tool\b|\bspdx-json\b",
    # a fuzzer run: ClusterFuzzLite, OSS-Fuzz's CIFuzz, cargo fuzz, Go's -fuzz, Atheris, Jazzer
    "fuzz": r"google/clusterfuzzlite/|google/oss-fuzz/|\bcargo\s+(?:\+\S+\s+)?fuzz\s+(?:run|build)\b"
    r"|\bgo test\b[^\n]*\s-fuzz\b|\batheris\b|\bjazzer\b",
    # a dependency audit for known vulnerabilities that CI_SCANNERS misses or overcounts: Ruby, PHP, Elixir, .NET, a
    # container image's packages; and, read again, Rust and Python, where its cargo_audit counts `cargo deny check
    # licenses` (no advisories) and its pip_audit a "safety check" in a message: here Safety is the command of a line
    "audit": r"\bbundler?[- ]audit\b|\bcomposer audit\b|\bmix (?:deps|hex)\.audit\b|\bdotnet list\b[^\n]*--vulnerable"
    r"|docker/scout-action|\bdocker scout cves\b|\bsnyk container (?:test|monitor)\b"
    r"|\bcargo[- ]audit\b|rustsec/audit-check|embarkstudios/cargo-deny-action"
    r"|\bcargo[- ]deny\b[^\n]*?\bcheck\b(?:[ \t]+-\S*(?:[ \t]+[^-\s]\S*)?)*(?:[ \t]+advisories\b|[ \t]*(?:\\|$))"
    r"|\bpip-audit\b|^[ \t]*(?:(?:uv run|uvx|pipx run|python3? -m)[ \t]+)?safety (?:check|scan)\b",
    # the secret scanners CI_SCANNERS does not know
    "secrets": r"\bdetect-secrets(?:-hook)?\s+(?:scan|audit)\b|\bsecretlint\b",
}
CI_SUPPLY = {k: re.compile(v, re.M) for k, v in CI_SUPPLY.items()}  # a run block is matched line by line: ^ and $
# The same, set as an action's input or an environment variable rather than run: matched on the workflow's text.
CI_SUPPLY_INPUTS = {
    "provenance": r"^\s*(?:-\s+)?(?:provenance|attestations|npm_config_provenance)\s*:\s*[\"']?(?:true|mode=max)\b",
    "sbom": r"^\s*(?:-\s+)?sbom\s*:\s*[\"']?true\b",
}
CI_SUPPLY_INPUTS = {k: re.compile(v, re.M) for k, v in CI_SUPPLY_INPUTS.items()}

# --- the practices of Issue #1 read in the workflows ----------------------------------------------------------------
# OPS_RUN is matched on what a workflow runs (scan.workflow_commands, with the root package.json scripts it calls and a
# command continued over lines joined), line by line. An action is matched where its `uses` value starts a line; one kept
# on a person's account is matched by its repo name alone, never by the account. scan.read_ops reads the rest from the
# workflow's shape: its triggers, its jobs' keys, a step's inputs. A gap within a line is bounded ({0,300}): a line that
# names a tool many times must not take a square of its length.
ACTION = lambda repos: r"^[\w.-]+/(?:%s)(?:/[\w./-]*)?@" % repos
# a command that runs a spell checker, not a file named for one (typos.toml) nor a sentence ("fix typos")
SPELL_RUN = (
    r"(?:^|[;&|(][ \t]*|\b(?:npx|pnpx|bunx|uvx|pipx run|exec|dlx|x|run|python3? -m)[ \t]+)"
    r"(?:codespell|typos|cspell)(?:-cli)?(?![\w./-])"
)
DEPLOY_K8S = (
    r"\bkubectl\b[^\n]{0,300}[ \t](?:apply|set image|rollout restart)\b|\bhelm upgrade\b|\bhelmfile (?:apply|sync)\b"
)
DEPLOY_K8S += r"|^azure/k8s-deploy@|\bargocd app sync\b"
DEPLOY_S3 = r"\baws s3 sync\b"
DEPLOY_OTHER = (
    r"\bwrangler (?:pages )?(?:deploy|publish)\b|^cloudflare/(?:wrangler-action|pages-action)@|\bfly(?:ctl)? deploy\b"
    r"|\baws (?:ecs update-service|lambda update-function-code|cloudformation deploy|deploy create-deployment)\b"
    r"|\bsam deploy\b|\bgcloud (?:beta )?(?:run|app|functions) deploy\b|\bgcloud run services (?:replace|update)\b"
    r"|\bvercel\b[^\n]{0,300}(?:[ \t]deploy\b|--prod\b)|\bnetlify deploy\b|\bfirebase deploy\b|\b(?:serverless|sls) deploy\b"
    r"|\bcdk(?:tf)? deploy\b|\bsst deploy\b|\bterraform apply\b|\bpulumi up\b|\brailway up\b|\bkamal deploy\b"
    r"|\bdocker stack deploy\b|\bnomad job run\b|\bdoctl apps create-deployment\b|\bheroku container:release\b"
    r"|^aws-actions/amazon-ecs-deploy-task-definition@|^google-github-actions/deploy-(?:cloudrun|appengine|cloud-functions)@"
    r"|^azure/(?:webapps-deploy|static-web-apps-deploy|functions-action|container-apps-deploy-action)@"
    r"|" + ACTION(r"action-hosting-deploy|vercel-action|actions-netlify|heroku-deploy")
)
# A package published: a publish command (not a dry run), or the publish actions of PyPI, npm and RubyGems.
PUBLISH = (
    r"(?:\b(?:npm|pnpm|bun|yarn(?: npm)?|lerna|changeset|cargo|uv|poetry|flit|hatch|pdm|maturin|vsce|ovsx|jsr|deno)"
    r"(?:[ \t]+(?:-r|--recursive|-w|--workspaces?|--filter[= ]\S+|-f[ \t]*\S+))*[ \t]+publish(?![\w:-])"
    r"|\btwine upload\b|\bgem push\b|\b(?:dotnet )?nuget push\b|\bmix hex\.publish\b|\b(?:dart|flutter) pub publish\b"
    r"|\bmaturin upload\b|\bmvnw?\b[^\n]{0,300}[ \t]deploy\b|\bgradlew?\b[^\n]{0,300}[ \t:]publish(?!tomavenlocal)\w*\b"
    r"|\brelease-plz\b)(?![^\n]{0,300}--dry-run)"
    r"|^pypa/gh-action-pypi-publish@|^rubygems/release-gem@|" + ACTION("npm-publish")
)
# A script of the repo named for a deploy or a publish: a package script or a task (`pnpm run publish-script`, `make
# deploy`) or a file (`tsx ./internal/scripts/deploy-dotcom.ts`). What it does is not read: kept apart from the deploys
# and the packages published. A root package.json script is read through (with_scripts) where the workflow calls it.
NAMED_SCRIPT = lambda word: (
    (
        r"\b(?:(?:pnpm|npm|yarn|bun)[ \t]+run|%s[ \t]+(?![ \t]*%s(?![\w:.-]))|(?:make|just|mise run|task))[ \t]*"
        r"(?:[\w.]+[:-])*%s(?:[:-][\w.]+)*(?![\w.])|(?:^|[\s/])[\w.-]*%s[\w.-]*\.(?:[cm]?[jt]s|sh|py|rb|ps1)\b"
    )
    % (PACKAGE_MANAGER_RUN, word, word, word)
)  # `npm publish`, `pnpm deploy` are the package manager's own commands
# a deploy that is not a dry run (`wrangler deploy --dry-run`, `aws s3 sync --dryrun`)
NOT_DRY = r"(?:%s)(?![^\n]{0,300}--dry-?run)"
# what an echo or a printf prints is not run: its words are dropped before OPS_RUN reads a command (scan.read_ops)
ECHOED = re.compile(r"\b(?:echo|printf)\b[^\n;&|]*")
OPS_RUN = {
    # dependencies and build outputs kept between runs: a cache action (a setup action's input: scan.read_ops)
    "cache": ACTION(r"cache|rust-cache|sccache-action|ccache-action"),
    "coverage": r"^codecov/codecov-action@|^coverallsapp/github-action@|--cov(?:er|erage)?\b|(?<![\w-])-cover(?:profile|pkg)?\b"
    r"|\bcargo (?:\+\S+ )?(?:llvm-cov|tarpaulin)\b|\bnyc\b|\bc8[ \t]|\bcoverage (?:run|report|xml|lcov|json|combine)\b"
    r"|\b(?:grcov|gcovr|kcov|coverlet|codecovcli|coveralls)\b|\bjacoco|\bkover|xplat code coverage"
    r"|\b%s[ \t]+%s|\b(?:make|just) %s" % (PACKAGE_MANAGER_RUN, SCRIPT("coverage"), TARGET("coverage")),
    "paths_action": ACTION(r"paths-filter|changed-files|get-changed-files"),
    "affected": r"\bnx\b[^\n]{0,300}\baffected\b|\bturbo\b[^\n]{0,300}--affected\b|\blerna (?:run|exec)\b[^\n]{0,300}--since\b"
    r"|\bmoon ci\b|\bmoon run\b[^\n]{0,300}--affected\b|\bbazel-diff\b|\btarget-determinator\b",
    # a package manager's filter on what changed since a commit: `pnpm --filter "...[origin/main]"`. Kept apart
    "affected_filter": r"--filter[= ][\"']?[^\s\"'\[]*\[",
    "spellcheck": ACTION(r"typos|actions-codespell|codespell-problem-matcher|cspell-action|codespell-action")
    + "|"
    + SPELL_RUN,
    "actionlint": CI_SCANNERS["actionlint"].pattern,
    "app_token": ACTION(r"(?:[\w-]+-)?github-app-token|workflow-application-token-action"),
    # a workflow that creates a release, not one that only reacts to it
    "release": r"\bgh release create\b|\bgoreleaser\b[^\n]{0,300}\brelease\b|release-please|semantic-release|\brelease-it\b"
    r"|\bjreleaser\b|^changesets/action@|^actions/create-release@|"
    + ACTION(r"action-gh-release|release-action|goreleaser-action|action-automatic-releases"),
    # a draft of the release notes, kept apart: a person may publish it
    "release_draft": ACTION("release-drafter"),
    "image_push": r"\bdocker (?:image |manifest )?push\b|\bdocker[- ]compose push\b"
    r"|\b(?:docker(?: buildx)?|depot) (?:build|bake)\b[^\n]{0,300}(?:--push\b(?![= ]false)|type=registry|push=true)"
    r"|\bimagetools create\b|\b(?:podman|buildah) (?:manifest )?push\b|\bskopeo copy\b|\bcrane (?:push|copy)\b"
    r"|\bko (?:build|publish|resolve)\b(?![^\n]{0,300}(?:--local|--push=false))|\bjib:build\b|\bgradlew?\b[^\n]{0,300}[ \t]jib\b",
    "image_build": ACTION(r"build-push-action|bake-action")
    + r"|\b(?:docker(?: buildx)?|depot) (?:build|bake)\b|\bdocker[- ]compose build\b|\b(?:podman|buildah) (?:build|bud)\b"
    r"|\bko (?:build|publish|resolve)\b|\bjib\b",
    "multi_arch": ACTION("setup-qemu-action")
    + r"|--platforms?[= ]+\S*/(?:arm64|aarch64)|\.platform=\S*/(?:arm64|aarch64)"
    r"|\bimagetools create\b",
    "deploy": NOT_DRY % (DEPLOY_OTHER + "|" + DEPLOY_K8S + "|" + DEPLOY_S3),
    # the deploys that may be a test cluster or a bucket of files rather than the product: kept apart as well
    "deploy_k8s": NOT_DRY % DEPLOY_K8S,
    "deploy_s3": NOT_DRY % DEPLOY_S3,
    "deploy_other": NOT_DRY % DEPLOY_OTHER,
    "deploy_script": NAMED_SCRIPT("deploy"),
    # GitHub Pages, often the docs: kept apart from the deploys
    "deploy_pages": r"^actions/deploy-pages@|" + ACTION(r"actions-gh-pages|github-pages-deploy-action"),
    "cloud_login": r"^aws-actions/configure-aws-credentials@|^google-github-actions/auth@|^azure/login@",
    "publish": PUBLISH,
    "publish_script": NAMED_SCRIPT("publish"),
    "stale": r"^actions/stale@",
    "labeler": r"^actions/labeler@",
    "title_check": ACTION("action-semantic-pull-request") + r"|commitlint",
}
OPS_RUN = {k: re.compile(v, re.M) for k, v in OPS_RUN.items()}
# Matched on the workflow's text, comments dropped. A value of false is off; an expression is on.
OPS_TEXT = {
    "concurrency": r"(?:^|[{,])[ \t]*cancel-in-progress[ \t]*:[ \t]*(?![\"']?false[\"']?[ \t]*(?:$|[,}]))[^\s,}]",
    "timeouts": r"(?:^|[{,])[ \t]*(?:-[ \t]+)?timeout-minutes[ \t]*:",
    # a docker build's cache kept between runs: kept apart from the cache of dependencies
    "cache_docker": r"\bcache-(?:from|to)\b",
}
OPS_TEXT = {k: re.compile(v, re.M) for k, v in OPS_TEXT.items()}
# A runner of Windows or macOS: a label, not a Rust target (x86_64-pc-windows-msvc) or a path.
OS_LABEL = re.compile(r"(?<![\w./-])(?:windows|macos)-(?:latest|\d+)\b")
# A step's input, by the action it is given to (scan.read_ops): a value of false or nothing is off.
SETUP_ACTION = re.compile(r"^[\w.-]+/setup-[\w.-]+@")
SETUP_CACHE = re.compile(r"^[ \t]*(?:enable-|bundler-)?cache[ \t]*:[ \t]*(?![\"']?(?:false)?[\"']?[ \t]*$)\S", re.M)
BUILD_PUSH_ACTION = re.compile(r"^[\w.-]+/(?:build-push-action|bake-action)@")
PUSH_INPUT = re.compile(
    r"^[ \t]*push[ \t]*:[ \t]*(?![\"']?false[\"']?[ \t]*$)\S|^[ \t]*outputs?[ \t]*:[^\n]{0,300}(?:type=registry|push=true)",
    re.M,
)
# an action that deploys only when told to: Fly's, Pulumi's, Netlify's command line
DEPLOY_STEP = {
    re.compile(r"^superfly/flyctl-actions@"): re.compile(r"\bdeploy\b"),
    re.compile(r"^pulumi/actions@"): re.compile(r"^[ \t]*command[ \t]*:[ \t]*[\"']?up\b", re.M),
    re.compile(r"^netlify/actions/cli@"): re.compile(r"\bdeploy\b"),
}
# an image's platforms naming ARM: a `platforms` input, or a `platform` key (a matrix of single-platform builds)
PLATFORMS_ARM = {"platforms": re.compile(r"arm64|aarch64"), "platform": re.compile(r"linux/(?:arm64|aarch64)")}
# The root package.json, parsed: what it names among its keys and its dependencies.
PKG_OPS = {
    "prettier": (("prettier",), ("prettier",)),
    "patches": (("patchedDependencies", "pnpm.patchedDependencies"), ("patch-package",)),
    "commitlint": ((), ("@commitlint/cli",)),
    "lint_staged": (("lint-staged",), ("lint-staged",)),
    "commitizen": (("config.commitizen",), ("commitizen",)),
}

# The token a workflow hands its jobs: a `permissions` key at the top of the workflow or of a job. write-all is not a scope.
TOP_PERMISSIONS = re.compile(r"^permissions\s*:[ \t]*([^\n]*)$", re.M)
JOBS_KEY = re.compile(r"^jobs\s*:[ \t]*$", re.M)
# A checkout step, and the input that keeps its token off the disk.
CHECKOUT = re.compile(r"^([ \t]*)(-[ \t]+)?uses\s*:\s*[\"']?actions/checkout@", re.M)
NO_PERSIST = re.compile(r"^\s*persist-credentials\s*:\s*[\"']?false\b", re.M)

# How a workflow that calls a coding agent holds it, or does not. Each is a fact about the workflow's
# text, not a verdict: a list of tools can hand over the whole shell, a list of bots opens a door.
CI_AGENT_FENCE = {
    "tools": r"allowed[_-]?tools|disallowed[_-]?tools",  # the agent's tools are listed
    # the list lets any shell command through: bash with no pattern after it, or bash(*)
    "bash": r"(?<!dis)allowed[_-]?tools[\"']?[ \t]*[:=]?[ \t]*[\"']?[^\n]*?(?:(?<![\w(])bash(?![\w(:])|bash\(\s*\*\s*\))"
    r"|(?<!dis)allowed[_-]?tools[\"']?[ \t]*:[ \t]*[|>]?-?[ \t]*\n(?:[ \t]+[^ \t\n][^\n]*\n|[ \t]*\n){0,40}?"
    r"[ \t]+(?:-[ \t]+)?[\"']?bash[\"']?,?[ \t]*(?:\n|$)",
    "bots": r"allowed_bots:\s*[\"']?[a-z0-9]",  # named bots may trigger it
    "assoc": r"author_association",  # triggered by members only
    "open": r"allowed_non_write_users:\s*[\"']?\*|allow-users:\s*[\"']?\*|allowed_bots:\s*[\"']?\*",  # anyone may
    "skip": r"dangerously-skip-permissions|--yolo\b|bypasspermissions|danger-full-access"
    r"|dangerously-bypass-approvals",  # the sandbox or the approvals switched off
    "review": r"anthropics/claude-code-security-review|/security-review\b",  # asked for a security review
}
CI_AGENT_FENCE = {k: re.compile(v) for k, v in CI_AGENT_FENCE.items()}
# The trigger that runs a workflow with the repo's secrets on a pull request from a fork. Read in
# the workflow's `on:` block only (ON_BLOCK): the word also shows up in conditions and group names.
FORK_TRIGGER = re.compile(r"\bpull_request_target\b")
ON_BLOCK = re.compile(r"^[\"']?on[\"']?[ \t]*:(.*?)(?=^\S|\Z)", re.M | re.S)
# An action a workflow uses, and what it is pinned to: a full commit SHA, or a tag or branch.
ACTION_USE = re.compile(r"\buses:\s*[\"']?([\w.-]+)/[\w./-]+@([\w./-]+)")
FIRST_PARTY_ACTIONS = ("actions", "github")

# A wait before a newly published package version may be installed, per file that can set one.
COOLDOWN = {
    "pnpm": {
        "pnpm-workspace.yaml": r"^\s*minimumreleaseage\s*:\s*[\"']?[1-9]",
        ".npmrc": r"^\s*minimum-release-age\s*=\s*[1-9]",
        "package.json": r"\"minimumreleaseage\"\s*:\s*[\"']?[1-9]",
    },
    "npm": {".npmrc": r"^\s*min-release-age\s*=\s*[1-9]"},
    "yarn": {".yarnrc.yml": r"^\s*npmminimalagegate\s*:\s*[\"']?[1-9]"},
    "bun": {"bunfig.toml": r"^\s*minimumreleaseage\s*=\s*[1-9]"},
    # a relative window ("7 days", "P7D"), not a fixed date, which pins a build instead
    "uv": {
        "pyproject.toml": r"^\s*exclude-newer\s*=\s*[\"'](?!\d{4}-)",
        "uv.toml": r"^\s*exclude-newer\s*=\s*[\"'](?!\d{4}-)",
    },
    "dependabot": {"dependabot": r"^\s*(?:-\s+)?cooldown\s*:"},
    # a value of one or more on a line that is not a comment, or the preset that sets one
    "renovate": {
        "renovate": r"^(?!\s*//)[^\n]*?[\"']?(?:minimumreleaseage|stabilitydays)[\"']?\s*:\s*[\"']?[1-9]"
        r"|[\"']:?minimumreleaseage\(\s*[1-9]|security:minimumreleaseagenpm"
    },
}
COOLDOWN = {k: {f: re.compile(rx, re.M) for f, rx in v.items()} for k, v in COOLDOWN.items()}

# Tools named in the root package.json (as a dependency) or the root pyproject.toml.
PACKAGE_TOOLS = {
    "oxlint": r"\"oxlint\"\s*:",
    "oxfmt": r"\"oxfmt\"\s*:",
    "biome": r"\"@biomejs/biome\"\s*:",
    "eslint": r"\"eslint\"\s*:",
    "prettier": r"\"prettier\"\s*:",
    "knip": r"\"knip\"\s*:",
    "tsgo": r"\"@typescript/native-preview\"\s*:",
    "tsgolint": r"\"oxlint-tsgolint\"\s*:",
    "typescript": r"\"typescript\"\s*:",
    "husky": r"\"husky\"\s*:",
    "lefthook": r"\"lefthook\"\s*:",
    "simple_git_hooks": r"\"simple-git-hooks\"\s*:",
    "lint_staged": r"\"lint-staged\"\s*:",
    "vitest": r"\"vitest\"\s*:",
    "jest": r"\"jest\"\s*:",
    "playwright": r"\"@playwright/test\"\s*:",
    "cypress": r"\"cypress\"\s*:",
}
# A dependency is the tool's own name, then a quote, a version or an extra: "mypy-primer" is not mypy.
NAME_END = r"(?=[\"'<>=~!\[ ;,])"
PYPROJECT_TOOLS = {
    "ruff": r"\[tool\.ruff|[\"']ruff" + NAME_END,
    "mypy": r"\[tool\.mypy|[\"']mypy" + NAME_END,
    "pyright": r"\[tool\.(?:based)?pyright|[\"'](?:based)?pyright" + NAME_END,
    "ty": r"\[tool\.ty\b|[\"']ty\s*[><=~\"']",
    "pyrefly": r"\[tool\.pyrefly|[\"']pyrefly" + NAME_END,
    "pytest": r"\[tool\.pytest|[\"']pytest\b",
}
# The package manager a repo pins, and its version: pnpm 11 and Yarn 4.15 wait before a new release by default.
PACKAGE_MANAGER = re.compile(r"\"packagemanager\"\s*:\s*\"(pnpm|yarn|npm|bun)@(\d+)\.(\d+)")
PACKAGE_TOOLS = {k: re.compile(v) for k, v in PACKAGE_TOOLS.items()}
PYPROJECT_TOOLS = {k: re.compile(v) for k, v in PYPROJECT_TOOLS.items()}

# What an agent hook runs after an edit or at the end of a turn: the check it wires into the agent's loop.
HOOK_CHECKS = {
    "format": r"(?<!--)(?<![a-z])(?:re)?format|\bfmt\b|prettier|oxfmt|gofmt|rustfmt",  # not "information", not --format
    "lint": r"lint|eslint|biome (?:check|lint)|ruff check|clippy|\bfix\b|ultracite",
    "types": r"\btsc\b|\btsgo\b|typecheck|type-check|\bmypy\b|\bpyright\b|\bty check\b|\bcargo check\b",
    "tests": r"\b(?:tests|vitest|jest|pytest)\b|\btest\b(?! -\w\b)",  # not the shell's `test -f`
    "check": r"\bchecks?\b",
}
HOOK_CHECKS = {k: re.compile(v) for k, v in HOOK_CHECKS.items()}
# The moment a hook runs, from the name its tool gives the event: before an action (it can block it),
# after one, or at the start of a session.
HOOK_BEFORE = re.compile(r"^(?:pre(?!compact)|before|permissionrequest|userpromptsubmit)")
HOOK_AFTER = re.compile(r"^(?:post|after|stop|subagentstop)")
HOOK_START = re.compile(r"^(?:session(?!end)|setup|worktree)")

# What the git hooks of a repo run (pre-commit config, lefthook, husky and hook scripts). Matched on
# the text without its comments and without commitlint, which checks a message, not the code
# (HOOK_NOISE). A test runner counts where it is run, not where it is installed or named.
HOOK_NOISE = re.compile(r"(?:^|\s)#.*$|commit-?lint", re.M)
GIT_HOOK_JOBS = {
    "lint": r"lint|\bbiome\b|\bruff\b|prettier|oxfmt|\bformat(?:s|ter|ting)?\b|\bfmt\b|ktfmt|swiftformat|clippy"
    r"|golangci|\bblack\b|gofmt|rustfmt",
    "types": r"\btsc\b|\btsgo\b|typecheck|type-check|\bmypy\b|\b(?:based)?pyright\b|\bty check\b|\bcargo check\b",
    "tests": r"(?:entry:|run:|^)[ \t]*(?!-[ \t])(?:[\w./-]+[ \t]+){0,4}(?:pytest|vitest|jest)\b|\bgo test\b|\bcargo test\b"
    r"|\b(?:npm|pnpm|yarn|bun)(?: run)? test\b",
    "secrets": r"gitleaks|trufflehog|detect-secrets|ggshield|secretlint|detect-private-key",
}
GIT_HOOK_JOBS = {k: re.compile(v, re.M) for k, v in GIT_HOOK_JOBS.items()}

# What the root instruction files tell an agent, matched on the text as written (case ignored). A
# full command counts wherever it is written (INSTRUCTIONS_SAY); a tool's bare name counts only in code
# formatting (INSTRUCTIONS_CODE on CODE_SPAN), since "Jest mocks" in a sentence names no command.
# Then a heading about security, and a rule on secrets.
SAY_RUN = PACKAGE_MANAGER_RUN
SECRET_WORDS = (
    r"(?:\b(?:secrets?|credentials?|passwords?|api[- _]?keys?|private keys?|access keys?"
    r"|(?:api|access|auth|bearer|secret|github|npm)[- _]?tokens?)\b|\.env\b)"
)
SAY = {
    "tests": r"\b(?:%s\s+%s|go test|cargo (?:nextest|test)|bun test|playwright test|mix test"
    r"|deno test|uv run (?:python -m )?pytest|python3? -m pytest|make %s|just %s|mise run [\w:-]*test[\w:-]*"
    r"|%s|nx (?:run|test|affected|run-many)[^\n`]*test|gradlew? [\w:-]*test"
    r"|rake (?:test|spec)|bazel test|dotnet test|swift test)\b"
    % (SAY_RUN, SCRIPT_TESTS, TARGET("tests?"), TARGET("tests?"), TURBO("test")),
    "lint": r"\b(?:%s\s+%s|cargo (?:clippy|fmt)|ruff (?:check|format)|biome (?:check|lint|format|ci)"
    r"|make %s|just %s|mise run [\w:-]*(?:lint|fmt|format)[\w:-]*|%s"
    r"|pre-commit run|lefthook run)\b"
    % (SAY_RUN, SCRIPT_LINT, TARGET("lint|fmt|format"), TARGET("lint|fmt|format"), TURBO("lint|fmt|format")),
    "types": r"\b(?:%s\s+(?:typecheck|type-check|check-types|types?:check|check:types|typescript:check|test:types|tsc)[\w:-]*"
    r"|tsc --noemit|cargo check|go vet|ty check|uv run (?:mypy|pyright|ty)|make %s|just %s"
    r"|mise run [\w:-]*type-?check[\w:-]*|turbo (?:run )?[\w:-]*type-?check[\w:-]*)\b"
    % (SAY_RUN, TARGET("type-?check"), TARGET("type-?check")),
    "security": r"^#{1,4}[^\n]*\bsecur",
    "secrets": r"\b(?:never|do not|don't|must not|must never|should never|avoid)\b[^\n]{0,80}"
    r"\b(?:commit|log|hardcod|hard-cod|expos|print|leak|stag|publish|past|shar|echo|stor|includ)\w*\b[^\n]{0,60}%s"
    r"|%s[^\n]{0,60}\b(?:must not|must never|should never|never|do not|don't)\b[^\n]{0,60}"
    r"\b(?:appear|be (?:committed|logged|hardcoded|hard-coded|exposed|printed|stored|shared|pasted))"
    % (SECRET_WORDS, SECRET_WORDS),
}
INSTRUCTIONS_SAY = {k: re.compile(v, re.I | re.M) for k, v in SAY.items()}
# A tool run by its name. Not its config file (jest.config.js), not a plugin of it (pytest-asyncio).
SAY_CODE = {
    "tests": r"\b(?:pytest|jest|vitest|rspec|tox|nox|phpunit|ctest|mocha)\b(?![.\w-])",
    "lint": r"\b(?:eslint|oxlint|golangci-lint|rubocop|prettier|oxfmt|gofmt|rustfmt|clippy|ktlint|swiftlint|ultracite"
    r"|(?<![\w./-])lint)\b(?![.\w-])",  # the word alone names the repo's own lint task: `hogli lint`
    "types": r"\b(?:tsc|tsgo|typecheck|type-check|mypy|pyright|basedpyright|pyrefly)\b(?![.\w-])",
}
INSTRUCTIONS_CODE = {k: re.compile(v, re.I) for k, v in SAY_CODE.items()}
CODE_SPAN = re.compile(r"```.*?```|`[^`\n]+`", re.S)
# A line of code whose command has "test" as a word of its own, after at most three others, or is a
# script of the repo named for it: `hogli test path`, `bunx turbo run lint test`, `./bin/test-agent`.
# Not a file or a folder named so (`test.py`, `tests/`), nor a shell command that only goes there.
CODE_TEST_LINE = re.compile(
    r"^\s*(?:\$\s+)?(?!(?:cd|ls|mkdir|rm|cp|mv|cat|git|echo|touch|source|export|import|from|def|class|if|for|while|return"
    r"|const|let|var|it|describe)\b)[a-z./][\w./@-]*(?:[ \t]+[\w./@-][\w:=./@-]*(?<![:=])){0,3}[ \t]+tests?(?![\w./:=-])"
    r"|^\s*(?:\$\s+)?\./(?:[\w.-]+/)*(?:[a-z0-9]+[-_])*tests?(?:[-_][a-z0-9]+)*(?:\.(?:sh|py|js|ts|rb))?(?=\s|$)",
    re.I | re.M,
)


def instructions_say(text):
    """What a root instruction file tells an agent: the keys of INSTRUCTIONS_SAY its text satisfies."""
    code = "\n".join(
        span.strip("`") for span in CODE_SPAN.findall(text)
    )  # one code span or one line of a block per line
    return sorted(
        {k for k, rx in INSTRUCTIONS_SAY.items() if rx.search(text)}
        | {k for k, rx in INSTRUCTIONS_CODE.items() if rx.search(code)}
        | ({"tests"} if CODE_TEST_LINE.search(code) else set())
    )


# A security policy that speaks of reports found or written with AI.
SECURITY_POLICY_AI = re.compile(
    r"ai[- ]generated|llm[- ]generated|auto(?:matically)?[- ]generated|generated (?:by|with|using) (?:an? )?(?:ai|llm)"
    r"|ai[- ]assist|used? (?:an? )?ai\b|ai (?:tools?|slop|reports?) |\bslop\b"
)
# A permission rule that keeps an agent away from secrets: a deny on env files, keys or credentials.
SECRET_RULE = re.compile(
    r"\.env(?![a-z])|secret|credential|\.pem|\.keys?\b|id_rsa|id_ed25519|password|\.aws|\.ssh"
    r"|\.p12|\.pfx|\.npmrc|\.netrc|\.kube"
)
# Other guards a package manager's file can set: refusing a version whose trust went down, install scripts off.
PACKAGE_GUARDS = {
    "trust_policy": {"pnpm-workspace.yaml": r"^\s*trustpolicy\s*:\s*[\"']?no-downgrade"},
    "no_scripts": {
        ".npmrc": r"^\s*ignore-scripts\s*=\s*true",
        ".yarnrc.yml": r"^\s*enablescripts\s*:\s*false",
        "bunfig.toml": r"^\s*ignorescripts\s*=\s*true",
    },
}
PACKAGE_GUARDS = {k: {f: re.compile(rx, re.M) for f, rx in v.items()} for k, v in PACKAGE_GUARDS.items()}

# Test files and code files, to follow how much of a repo's code is tests. Paths only.
CODE_FILE = re.compile(
    r"\.(?:[cm]?[jt]sx?|py|go|rs|java|kts?|rb|php|cs|swift|cc?|cpp|cxx|hpp|h|scala|exs?"
    r"|cljs?|cljc|vue|svelte|dart|lua|zig|ml|hs|erl)$",
    re.I,
)
# build/ and out/ are output at the root only: deeper, they are folders of source (packages/next/src/build/)
NOT_OWN_CODE = re.compile(
    r"(?:^|/)(?:node_modules|vendor|vendors|third_party|third-party|dist)/|^(?:build|out)/"
    r"|\.d\.ts$|\.min\.js$",
    re.I,
)
TEST_FILE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|e2e|testing|testsuite|integration[-_]tests?)/"
    r"|[._-](?:test|tests|spec|specs|e2e|cy)\.[a-z]+$|(?:^|/)(?:test_[^/]+|tests|conftest)\.py$"
    r"|_test\.(?:go|py|rs|rb|exs?|dart|cc|cpp|c)$|_spec\.rb$",
    re.I,
)
JVM_TEST_FILE = re.compile(
    r"(?:Tests?|Spec|IT)\.(?:java|kts?|cs|swift|scala)$|(?:^|/)Test[A-Z]\w*\.(?:java|kts?|scala)$"
)


# Agent signatures on commits. Identities are matched against "name <email>", lowercased,
# for the author and every Co-authored-by trailer. Only agent addresses are listed: a person
# committing from a vendor's domain is not an agent.
COMMIT_IDENTITY = {
    "claude": r"noreply@anthropic\.com|\bclaude(?: code)?\[bot\]",
    "cursor": r"cursoragent@cursor\.com|^cursor agent <|\bcursor\[bot\]",
    "copilot": r"copilot-swe-agent|\+copilot@users\.noreply\.github\.com|^copilot <",
    "codex": r"(?:noreply|codex)@openai\.com|chatgpt-codex-connector|^codex <",
    "gemini": r"gemini-cli|gemini-code-assist|^gemini(?: cli)? <",
    "jules": r"google-labs-jules",
    "amp": r"amp@ampcode\.com",
    "devin": r"devin-ai-integration",
    "aider": r"\(aider\) <|^aider <",
    "opencode": r"^opencode <|opencode-agent|noreply@opencode\.ai",
    "droid": r"factory-droid|droid@factory\.ai",
    "openhands": r"\bopenhands\b",
    "warp": r"agent@warp\.dev",
    "junie": r"junie@jetbrains\.com|^junie <",
    "kiro": r"^kiro(?: agent)? <|noreply@kiro\.dev",
    "windsurf": r"^(?:windsurf|cascade) <",
    "lovable": r"lovable-dev\[bot\]|gpt-engineer-app\[bot\]",
    "v0": r"\bv0\[bot\]",
    "codegen": r"codegen-sh",
    "sweep": r"sweep-ai",
}
COMMIT_IDENTITY = {k: re.compile(v) for k, v in COMMIT_IDENTITY.items()}
COMMIT_BODY = {
    "claude": r"generated with \[?claude code",
    "amp": r"^amp-thread(?:-id)?:",
    "codex": r"generated with \[?codex",
    "cursor": r"(?:generated|made) with \[?cursor",
    "opencode": r"generated with \[?opencode",
    "copilot": r"generated with \[?github copilot",
    "gemini": r"generated with \[?gemini",
    "droid": r"generated with \[?droid",
    "warp": r"generated with \[?warp",
}
COMMIT_BODY = {k: re.compile(v, re.M) for k, v in COMMIT_BODY.items()}

# Identities kept for discovery of new agent signatures. Only an agent's mailbox is kept, and
# its display name only when it reads as an agent or a model. A person's name or address is
# never written out, even when the person commits from an agent vendor's domain.
AGENT_MAILBOX = re.compile(
    r"<(?:noreply|no-reply|agents?(?:-noreply)?|bot|bugbot|cursor-?agent|codex|chatgpt|claude(?:-code|-bot)?"
    r"|amp|devin|oz-agent|droid|opencode|copilot)@[^<>]+>$"
)
AGENT_NAME = re.compile(
    r"\[bot\]|claude|codex|cursor|copilot|gemini|gpt|opus|sonnet|haiku|fable|mythos|aider|opencode|mastra"
    r"|agent|\bbot\b|kimi|glm|grok|deepseek|qwen|minimax"
)
PERSONAL_NOREPLY = re.compile(r"@users\.noreply\.github\.com")


def agent_name(name):
    """A display name as it may be stored: kept when it reads as an agent or a model, else blank."""
    return name if AGENT_NAME.search(name) else ""


def discovery_identity(ident):
    """`name <email>` as it may be stored, or None when the address is not an agent's mailbox."""
    if PERSONAL_NOREPLY.search(ident) or not AGENT_MAILBOX.search(ident):
        return None
    name, _, mail = ident.rpartition("<")
    return ("%s <%s" % (agent_name(name.strip()), mail)).strip()


@functools.lru_cache(maxsize=None)
def still_valid(rule_id, path):
    """Whether a path kept by an earlier scan still counts under the rules as they are now."""
    linked = match_link(path)
    if linked and linked[0] == rule_id and not linked[1]:
        return True
    return any(r == rule_id and not shipped for r, shipped, _ in match(path))
