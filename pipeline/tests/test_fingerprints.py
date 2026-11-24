"""The fingerprints of fingerprints.py: for every rule, paths or texts it must match and near misses it must not.

The near misses come from what each rule leaves out: shipped material
(templates, examples, fixtures, tests, evals), a skill's own reference files, product plugin
folders, personal settings, and people committing from an agent vendor's domain. Every rule
must have an example here: a new rule without one fails test_every_rule_has_examples.
"""

import re
import time
import unittest

import base  # noqa: F401  (puts pipeline/ on the path)
import fingerprints as fp

# rule: (paths it counts, near misses it must not count)
PATHS = {
    "claude_md": (
        ["CLAUDE.md", "packages/api/CLAUDE.md", ".claude/CLAUDE.md", "claude.md"],
        ["docs/claude.md", "CLAUDE.md.bak", "MY_CLAUDE.md"],
    ),
    "agents_md": (
        ["AGENTS.md", "apps/web/AGENTS.md", "agents.md"],
        ["docs/agents.md", "MY_AGENTS.md", "AGENTS.md.orig"],
    ),
    "gemini_md": (["GEMINI.md", "packages/cli/GEMINI.md"], ["docs/gemini.md"]),
    "cursor_rules": (
        [".cursorrules", ".cursor/rules/style.mdc", "web/.cursor/rules/api.mdc"],
        [".cursor/rules", ".cursor/mcp.json"],
    ),
    "copilot_instructions": (
        [".github/copilot-instructions.md", ".github/instructions/api.instructions.md"],
        [".github/instructions/api.md", "docs/copilot-instructions.md"],
    ),
    "windsurf_rules": ([".windsurfrules", ".windsurf/rules/style.md"], [".windsurf/workflows/release.md"]),
    "cline_roo_rules": (
        [".clinerules", ".clinerules/style.md", ".roo/rules-code/style.md", ".roomodes", ".kilocode/rules/style.md"],
        [".clinerules.bak", ".roo/mcp.json"],
    ),
    "other_rules": (
        [".junie/guidelines.md", ".kiro/steering/product.md", "WARP.md", ".github/chatmodes/plan.md"],
        ["docs/WARP.md", ".junie/notes.md"],
    ),
    "skills": (
        [".claude/skills/review/SKILL.md", ".agents/skills/release/SKILL.md", "web/.codex/skills/a/b/SKILL.md"],
        ["skills/review/SKILL.md", ".claude/skills/SKILL.md", ".claude/skills/review/README.md"],
    ),
    "commands": (
        [".claude/commands/review.md", ".github/prompts/fix.prompt.md", ".cursor/commands/ship"],
        [".claude/commands/review.txt", ".github/prompts/fix.md"],
    ),
    "subagents": (
        [".claude/agents/reviewer.md", ".github/agents/triage.md", ".factory/droids/qa.md"],
        [".claude/agents/reviewer.json", "docs/agents/reviewer.md"],
    ),
    "mcp_config": (
        [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "apps/web/.mcp.json"],
        ["mcp.json", "plugins/claude/.mcp.json", "integrations/cursor/.cursor/mcp.json"],
    ),
    "hooks_files": (
        [".claude/hooks/format.sh", ".cursor/hooks.json", ".codex/hooks/pre.sh"],
        ["src/hooks/useAuth.ts", "hooks/pre-commit", ".husky/pre-commit"],
    ),
    "shared_settings": (
        [".claude/settings.json", ".codex/config.toml", "opencode.json", ".opencode/opencode.jsonc"],
        [".claude/settings.local.json", ".vscode/settings.json"],
    ),
    "plugin_manifest": (
        [".claude-plugin/plugin.json", ".cursor-plugin/marketplace.json"],
        [".claude-plugin/README.md"],
    ),
    "agent_ignore": ([".cursorignore", ".aiexclude", ".claudeignore"], [".gitignore", ".dockerignore"]),
    "ai_docs": (
        ["llms.txt", "llms-full.txt", "docs/llms.txt", "apps/site/public/llms-full.txt"],
        [".claude/skills/sdk/references/llms.txt", "packages/sdk/llms.txt", "llms.md"],
    ),
    "spec_framework": (
        [
            ".specify/memory/constitution.md",
            "openspec/specs/auth/spec.md",
            "specs/001-login/spec.md",
            ".kiro/specs/login/design.md",
        ],
        ["specs/login/spec.md", "openspec/README.md"],
    ),
    "plans": (
        ["docs/plans/2026-01-auth.md", "PLAN.md", "PLANS.md", ".claude/plans/refactor.md", "exec-plans/a.md"],
        ["plans.md", ".claude/plans/.gitkeep", ".claude/skills/planner/references/plan.md", ".claude/commands/plan.md"],
    ),
    "task_tracker": (
        [".beads/issues.jsonl", ".taskmaster/tasks/tasks.json", "backlog/tasks/task-1.md"],
        ["backlog/README.md", "backlog/tasks/task-1.json"],
    ),
    "memory": (
        ["memory-bank/activeContext.md", ".serena/project.yml", "MEMORY.md", ".claude/memory/notes.md"],
        ["docs/MEMORY.md", "src/memory/cache.ts"],
    ),
    "adr": (
        ["docs/adr/0001-use-postgres.md", "docs/decisions/0002-monorepo.md", "adr/0003.md"],
        ["docs/adr/README.txt", "src/decisions/rules.ts"],
    ),
    "parallel_setup": (
        [".cursor/worktrees.json", ".worktreeinclude", "conductor.json", ".superset/setup.sh"],
        [".cursor/worktree.json", "scripts/worktrees.sh"],
    ),
    "cloud_agent_env": (
        [
            ".github/workflows/copilot-setup-steps.yml",
            ".cursor/environment.json",
            ".codex/environments/env.toml",
            ".devin/setup.sh",
        ],
        [".github/workflows/ci.yml", "environment.json"],
    ),
    "ai_review_config": (
        [
            ".coderabbit.yaml",
            "BUGBOT.md",
            ".cursor/BUGBOT.md",
            ".greptile/config.json",
            "REVIEW.md",
            ".claude/commands/review-pr.md",
        ],
        ["docs/REVIEW.md", "CODE_REVIEW.md"],
    ),
    "rules_sync_tool": ([".rulesync/rules/style.md", "rulesync.jsonc", ".ruler/instructions.md"], ["rulesync.yaml"]),
    "ai_policy": (
        ["AI_POLICY.md", ".github/AI-USAGE.md", "AI_CONTRIBUTIONS.md", "docs/AI_GUIDELINES.md"],
        ["AI_POLICY.txt", "docs/AI.md"],
    ),
    "workflows": (
        [".github/workflows/ci.yml", ".github/workflows/review.md"],
        ["packages/x/.github/workflows/ci.yml", ".github/workflows/sub/ci.yml"],
    ),
    "skill_files": (["skills/review/SKILL.md", ".claude/skills/review/SKILL.md"], ["skills/SKILL.md"]),
    # --- checks
    "oxlint": (
        [".oxlintrc.json", ".oxlintrc.jsonc", "oxlint.config.ts", "apps/web/.oxlintrc.json"],
        ["docs/oxlint.md", ".oxlintrc.json.bak", "oxlint.json", "node_modules/oxlint/.oxlintrc.json"],
    ),
    "oxfmt": ([".oxfmtrc.json", "oxfmt.config.ts", "web/.oxfmtrc.jsonc"], ["oxfmt.md", ".oxfmtrc.yaml"]),
    "biome": (
        ["biome.json", "biome.jsonc", "packages/ui/biome.json"],
        ["biome.yaml", "docs/biome.md", "mybiome.json", "examples/app/biome.json"],
    ),
    "eslint": (
        [".eslintrc", ".eslintrc.json", "eslint.config.mjs", "web/eslint.config.ts"],
        [".eslintignore", ".eslintrc.json.bak", "docs/eslint.md", "templates/app/eslint.config.js"],
    ),
    "prettier": (
        [".prettierrc", ".prettierrc.json", ".prettierrc.yaml", "prettier.config.js"],
        [".prettierignore", "docs/prettier.md", "prettier.config.md"],
    ),
    "knip": (
        ["knip.json", ".knip.jsonc", "knip.config.ts", "knip.ts", "knip.config.jsonc"],
        ["knip.md", "docs/knip.json5"],
    ),
    "import_rules": (
        [
            ".dependency-cruiser.js",
            ".dependency-cruiser.cjs",
            ".madgerc",
            "tach.toml",
            ".importlinter",
            "dependency-cruiser.config.mjs",
        ],
        ["docs/dependency-cruiser.md", "tach.toml.bak"],
    ),
    # rule files only (js/ts/py/yaml/go/grit; .grit/ also md): not the README, changelog or package.json
    # of a plugin folder, not a .rs file; the shipped test runs on the file's own folder too
    "custom_lint": (
        [
            "tools/biome-plugins/no-foo.grit",
            "rules/no-console.grit",
            "tools/eslint-rules/no-foo.js",
            "eslint-local-rules.js",
            "sgconfig.yml",
            ".semgrep/rules.yml",
            "scripts/oxlint-plugins/a.js",
            ".grit/rule.md",
            "tools/eslint-rules/no-foo.ts",
            "lint-rules/a.py",
            "eslint-rules/a.go",
            "eslint-plugin-foo/rules/a.cjs",
        ],
        [
            "docs/eslint-rules/no-foo.md",
            "website/semgrep/rules.yml",
            "src/eslint-rules.md",
            "node_modules/eslint-plugin-react/index.js",
            "eslint-rules/README.md",
            "eslint-rules/CHANGELOG.md",
            "eslint-rules/package.json",
            "eslint-plugin-foo/README.md",
            "eslint-rules/a.rs",
            ".clj-kondo/hooks/a.clj",
            "biome-plugins/README.md",
            "eslint-rules/__tests__/x.js",
            "biome-plugins/fixtures/a.grit",
        ],
    ),
    # hook scripts by name in a hooks folder; an agent's own hooks folder is not a git hooks folder
    "git_hooks": (
        [
            ".husky/pre-commit",
            ".husky/pre-push",
            "lefthook.yml",
            ".lefthook.yaml",
            "lefthook-local.yml",
            ".pre-commit-config.yaml",
            ".githooks/pre-push",
            "prek.toml",
            ".husky/pre-commit.sh",
            ".vite-hooks/pre-commit",
            "githooks/commit-msg",
            "git-hooks/prepare-commit-msg",
            ".git-hooks/post-merge",
            "scripts/hooks/post-checkout",
            "hooks/pre-rebase",
            ".husky/post-commit",
        ],
        [
            ".husky/_/husky.sh",
            ".husky/install.mjs",
            "docs/lefthook.md",
            ".githooks/README.md",
            ".husky/pre-commit-foo",
            ".husky/post-rewrite",
            "hooks/useAuth.ts",
            ".claude/hooks/pre-commit",
            ".cursor/hooks/pre-commit",
            "packages/a/.agents/hooks/pre-commit",
            "node_modules/a/.husky/pre-commit",
        ],
    ),
    "lint_staged": (
        [".lintstagedrc", ".lintstagedrc.json", "lint-staged.config.js", "lint-staged.config.mjs"],
        ["docs/lint-staged.md", "lint-staged.json"],
    ),
    "vitest": (
        [
            "vitest.config.ts",
            "vitest.workspace.ts",
            "packages/a/vitest.config.mts",
            "vitest.e2e.config.ts",
            "vitest.config.e2e.ts",
        ],
        ["vitest.setup.ts", "vitest.config.json", "docs/vitest.md"],
    ),
    "jest": (
        ["jest.config.js", "jest.config.ts", "jest.config.json", "apps/api/jest.config.cjs"],
        ["jest.setup.js", "jest.config.yaml", "jest-config.js"],
    ),
    "playwright": (
        ["playwright.config.ts", "playwright-ct.config.ts", "e2e/playwright.config.ts"],
        ["playwright.json", "playwright/config.ts", "playwright.config.md"],
    ),
    "cypress": (
        ["cypress.config.ts", "cypress.config.js", "web/cypress.config.mjs", "cypress.json"],
        ["cypress/e2e/home.cy.ts", "docs/cypress.md"],
    ),
    "pytest": (
        ["pytest.ini", "conftest.py", "tests/conftest.py", "pkg/tests/conftest.py"],
        ["conftest.pyc", "pytest.ini.bak", "docs/conftest.md"],
    ),
    "mutation_tests": (
        [
            "stryker.conf.js",
            "stryker.config.json",
            "mutants.toml",
            ".cargo/mutants.toml",
            "infection.json5",
            "infection.json.dist",
            "x.stryker.config.mjs",
        ],
        ["docs/stryker.md", "infection.yml", "docs/mutants.md"],
    ),
    "checks_ext": (
        [
            ".claude/skills/run-tests/SKILL.md",
            ".claude/skills/ci/SKILL.md",
            ".claude/commands/lint.md",
            ".claude/agents/test-runner.md",
            ".github/prompts/typecheck.prompt.md",
            ".codex/prompts/pytest_fix.md",
            ".claude/commands/testers.md",
            ".claude/commands/qabot-fix.md",
            ".claude/commands/flaky-tests.md",
            ".claude/commands/flakey.md",
            ".claude/commands/fuzzing.md",
            ".claude/commands/verify-all.md",
            ".claude/commands/fmt.md",
            ".claude/commands/formatting.md",
        ],
        [
            ".claude/commands/latest.md",
            ".claude/commands/format.md",
            ".claude/commands/contest.md",
            ".claude/commands/protest.md",
            ".claude/skills/deploy/SKILL.md",
            ".claude/skills/run-tests/README.md",
            "skills/run-tests/SKILL.md",
            ".claude/commands/ship.md",
        ],
    ),
    # --- security
    "security_md": (
        [
            "SECURITY.md",
            ".github/SECURITY.md",
            "docs/SECURITY.md",
            "SECURITY.rst",
            "SECURITY.txt",
            ".github/SECURITY.rst",
        ],
        [
            "packages/a/SECURITY.md",
            "SECURITY.md.bak",
            "docs/security/overview.md",
            ".github/docs/SECURITY.md",
            "docs/security.md",
            "doc/security.md",
            "SECURITY.html",
        ],
    ),
    "dependabot": (
        [".github/dependabot.yml", ".github/dependabot.yaml"],
        ["dependabot.yml", "packages/a/.github/dependabot.yml", ".github/workflows/dependabot-merge.yml"],
    ),
    "renovate": (
        ["renovate.json", ".renovaterc", ".renovaterc.json", ".github/renovate.json5", ".gitlab/renovate.json"],
        ["docs/renovate.json", "packages/a/renovate.json", "renovate.md", ".github/workflows/renovate.yml"],
    ),
    "codeowners": (["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"], ["packages/a/CODEOWNERS", "CODEOWNERS.md"]),
    "zizmor": (
        ["zizmor.yml", ".github/zizmor.yml", ".zizmor.yaml"],
        ["docs/zizmor.yml", "zizmor.md", ".github/workflows/zizmor.yml"],
    ),
    "secret_scan": (
        [
            ".gitleaks.toml",
            ".gitleaksignore",
            ".secrets.baseline",
            ".gitguardian.yaml",
            ".trufflehog.yml",
            ".secretlintrc.json",
            "gitleaks.toml",
            ".github/gitleaks.toml",
        ],
        ["config/.gitleaks.toml", ".github/workflows/gitleaks.yml", "docs/gitleaks.md"],
    ),
    "dep_audit": (
        [
            "socket.yml",
            ".snyk",
            "osv-scanner.toml",
            ".trivyignore",
            "trivy.yaml",
            "audit-ci.json",
            ".grype.yaml",
            "deny.toml",
            ".cargo/audit.toml",
            ".github/osv-scanner.toml",
        ],
        ["packages/a/.snyk", "docs/socket.yml", "snyk.md", "osv-scanner.md"],
    ),
    "threat_model": (
        ["THREAT_MODEL.md", "docs/threat-model.md", "docs/security/threatmodel-api.md"],
        ["docs/threat-model.txt", "docs/threats.md", "threat-model/README.md"],
    ),
    # code in a fuzz folder, a fuzz target named so, a ClusterFuzzLite setup; inside a test folder too. Not the docs,
    # the corpus or the crash files a fuzzer keeps, nor a word that only starts with fuzz (fuzzy search)
    "fuzz_tests": (
        [
            "fuzz/fuzz_targets/parse.rs",
            "fuzz/Cargo.toml",
            "crates/a/fuzz/fuzz_targets/x.rs",
            "pkg/db/fuzz_test.go",
            "derp/derp_fuzz_test.go",
            "tests/fuzz/test_parser.py",
            "test/external/fuzz_shape_ops.py",
            ".clusterfuzzlite/build.sh",
            "src/fuzzer/fuzzer.cpp",
            "fuzzing/gst-audio.c",
            "lib/x/regress/fuzz/fuzz_json.c",
            "tests/app/test_engine_fuzz.py",
        ],
        [
            "docs/reference/fuzz/run.mdx",
            "fuzz/README.md",
            "fuzz/corpus/parse/test_1",
            "fuzz/artifacts/crash-1",
            "src/fuzzy/search.ts",
            "lib/fuzzy_match.py",
            "fuzzysearch/a.go",
            "vendor/a/fuzz/x.go",
            "examples/fuzz/x.rs",
            "fuzz.md",
            "testdata/fuzz/FuzzParse/abc",
        ],
    ),
    "oss_scanner": (
        [".oss-scanner/config.yml", "oss-scanner/rules.yaml", ".github/oss-scanner/policy.json"],
        ["packages/a/.oss-scanner/config.yml", "docs/oss-scanner.md"],
    ),
    "agent_permissions": (
        [".cursor/cli.json", ".cursor/sandbox.json", ".codex/rules/default.rules", ".gemini/policies/policy.toml"],
        [".cursor/rules/a.mdc", ".gemini/settings.json", ".codex/rules/readme.md"],
    ),
    "devcontainer": (
        [".devcontainer/devcontainer.json", ".devcontainer.json", ".devcontainer/node/devcontainer.json"],
        ["packages/a/.devcontainer/devcontainer.json", ".devcontainer/Dockerfile", ".devcontainer/README.md"],
    ),
    "security_ext": (
        [
            ".claude/skills/security-review/SKILL.md",
            ".claude/commands/security-review.md",
            ".claude/agents/vulnerability-scanner.md",
            ".github/prompts/threat-model.prompt.md",
            ".claude/commands/cve-triage.md",
            ".claude/commands/dependabot-alerts.md",
            ".claude/commands/audit-dependencies.md",
            ".claude/commands/dependency-audit.md",
            ".claude/commands/advisory.md",
            ".claude/commands/advisories.md",
        ],
        [
            ".claude/commands/advisory-board.md",
            ".claude/commands/insecure.md",
            ".claude/commands/securities.md",
            ".claude/skills/deploy/SKILL.md",
            ".claude/commands/ship.md",
        ],
    ),
    # --- read for their content
    "pkg_files": (
        ["package.json", "pnpm-workspace.yaml", ".npmrc", ".yarnrc.yml", "bunfig.toml", "pyproject.toml", "uv.toml"],
        [
            "packages/api/package.json",
            "package-lock.json",
            "docs/pyproject.toml",
            "pnpm-lock.yaml",
            "ui/.npmrc",
            "a/b/pnpm-workspace.yaml",
        ],
    ),
    # the same files one or two folders down; the root stays pkg_files, three folders down is out
    "pkg_nested": (
        ["ui/.npmrc", "ui/pnpm-workspace.yaml", "apps/web/.yarnrc.yml", "apps/web/bunfig.toml", "ui/uv.toml"],
        [
            ".npmrc",
            "pnpm-workspace.yaml",
            "a/b/c/.npmrc",
            "a/b/c/bunfig.toml",
            "ui/package.json",
            "ui/pyproject.toml",
            "ui/.npmrc.bak",
        ],
    ),
    # --- issue templates and what follows
    "issue_templates": (
        [
            ".github/ISSUE_TEMPLATE/bug.yml",
            ".github/issue_template/config.yml",
            "ISSUE_TEMPLATE.md",
            ".github/ISSUE_TEMPLATE.md",
            "docs/issue_template.md",
            "docs/ISSUE_TEMPLATE/feature.md",
        ],
        [
            ".github/ISSUE_TEMPLATE",
            "packages/a/.github/ISSUE_TEMPLATE/bug.yml",
            "ISSUE_TEMPLATE.txt",
            "web/ISSUE_TEMPLATE.md",
            ".github/ISSUE_TEMPLATES/bug.md",
        ],
    ),
    "pr_template": (
        [
            ".github/pull_request_template.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            "pull_request_template.md",
            "docs/pull_request_template.md",
            ".github/PULL_REQUEST_TEMPLATE/feature.md",
        ],
        ["web/.github/pull_request_template.md", ".github/pull_request_template.md.bak", "pr_template.md"],
    ),
    "toolchain_files": (
        [
            ".nvmrc",
            ".node-version",
            ".python-version",
            ".ruby-version",
            "rust-toolchain",
            "rust-toolchain.toml",
            ".tool-versions",
            "mise.toml",
            ".mise.toml",
            ".mise/config.toml",
            ".config/mise.toml",
        ],
        ["web/.nvmrc", "apps/api/.python-version", "rust-toolchain.md", ".nvmrc.bak", "mise.lock", ".go-version"],
    ),
    "toolchain_other": (
        [".go-version", ".java-version", ".terraform-version", ".sdkmanrc"],
        ["a/.go-version", ".nvmrc"],
    ),
    "compose": (
        [
            "docker-compose.yml",
            "compose.yaml",
            "docker-compose.dev.yml",
            "compose.override.yaml",
            "docker-compose-test.yaml",
            "deploy/docker-compose.yml",
            "infra/local/compose.yml",
            ".devcontainer/docker-compose.yml",
        ],
        [
            "composer.json",
            "composer.yml",
            "a/b/c/docker-compose.yml",
            "docker-compose.yml.j2",
            "compose.json",
            "my-compose.yml",
            "examples/basic/docker-compose.yml",
            # a workflow named for Compose
            ".github/workflows/docker-compose.yml",
            ".github/workflows/docker-compose-tests.yml",
        ],
    ),
    "task_runner": (
        ["Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", ".justfile", "Taskfile.yml", "taskfile.yaml"],
        ["src/Makefile", "Makefile.am", "Makefile.in", "justfile.md", "Taskfile.json", "cmake/Makefile"],
    ),
    "editorconfig": ([".editorconfig"], ["web/.editorconfig", ".editorconfig.bak", "editorconfig"]),
    "editor_settings": (
        [".vscode/settings.json", ".vscode/extensions.json", ".zed/settings.json"],
        [".vscode", ".vscode/launch.json", ".idea/workspace.xml", "web/.vscode/settings.json", ".vscode/mcp.json"],
    ),
    "editor_other": (
        [".vscode/launch.json", ".vscode/tasks.json", "project.code-workspace", ".zed/tasks.json"],
        [".vscode/settings.json", ".idea/misc.xml", "web/.vscode/launch.json"],
    ),
    "env_example": (
        [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.local.example",
            ".env.production.example",
            ".env.example.local",
            "example.env",
            "sample.env",
            "env.example",
            "apps/web/.env.example",
            "docker/.env.tpl",
        ],
        [
            ".env",
            ".env.local",
            ".env.production",
            ".envrc",
            "src/env.ts",
            "a/b/c/.env.example",
            "examples/next/.env.example",
            "templates/app/.env.example",
        ],
    ),
    "stale_config": ([".github/stale.yml", ".github/stale.yaml"], ["stale.yml", ".github/workflows/stale.yml"]),
    "nix_env": (
        ["flake.nix", "shell.nix", "devbox.json", "devenv.nix"],
        [".envrc", "default.nix", "nix/flake.nix", "flake.lock", "devbox.lock"],
    ),
    "patches": (
        ["patches/react-native+0.74.0.patch", ".yarn/patches/lodash-npm-4.17.21.patch", "patches/fix.diff"],
        ["patches/README.md", "packages/a/patches/x.patch", "src/fix.patch", "patches"],
    ),
    "labeler_config": (
        [".github/labeler.yml", ".github/labeler.yaml"],
        [".github/workflows/labeler.yml", "labeler.yml"],
    ),
    "formatter_config": (
        [
            ".prettierrc",
            ".prettierrc.json",
            "prettier.config.mjs",
            "biome.json",
            "web/biome.jsonc",
            ".oxfmtrc.json",
            "rustfmt.toml",
            ".rustfmt.toml",
            ".clang-format",
            "_clang-format",
            "dprint.json",
            ".dprint.jsonc",
            "taplo.toml",
            ".taplo.toml",
            "stylua.toml",
            ".stylua.toml",
            ".swiftformat",
            ".swift-format",
            ".formatter.exs",
            "packages/ui/.prettierrc",
        ],
        [
            ".prettierignore",
            ".clang-format-ignore",
            "rustfmt.md",
            "a/b/c/.prettierrc",
            "examples/a/.prettierrc",
            ".clang-tidy",
            ".eslintrc.json",
        ],
    ),
    "formatter_other": (
        [".scalafmt.conf", ".ocamlformat", ".php-cs-fixer.dist.php", "treefmt.toml", ".yamlfmt", ".cmake-format.yaml"],
        [".scalafix.conf", ".php-cs-fixer.cache", "treefmt.nix"],
    ),
    "coverage_config": (
        [
            "codecov.yml",
            ".codecov.yml",
            ".github/codecov.yml",
            ".coveragerc",
            ".nycrc",
            ".nycrc.json",
            ".c8rc.json",
            ".coveralls.yml",
            "coveralls.yml",
        ],
        # the last: a vendored copy of another project
        [
            "codecov.sh",
            "coverage/lcov.info",
            ".coverage",
            "a/b/c/.coveragerc",
            "codecov.json",
            "vendored/lib/codecov.yml",
        ],
    ),
    "coverage_other": ([".simplecov", "tarpaulin.toml", ".tarpaulin.toml"], ["simplecov.rb", "coverage.toml"]),
    "spellcheck_config": (
        [
            "typos.toml",
            "_typos.toml",
            ".typos.toml",
            "cspell.json",
            ".cspell.json",
            "cspell.config.yaml",
            "cspell.yaml",
            ".vscode/cspell.json",
            ".codespellrc",
            ".github/_typos.toml",
        ],
        ["typos.md", "cspell-words.txt", ".codespell-ignore", "codespell.txt"],
    ),
    "actionlint_config": (
        [".github/actionlint.yml", ".github/actionlint.yaml"],
        ["actionlint.yml", ".github/actionlint-matcher.json", ".github/workflows/actionlint.yml"],
    ),
    "changelog": (
        [
            "CHANGELOG.md",
            "changelog.md",
            "CHANGELOG",
            "CHANGES.rst",
            "HISTORY.md",
            "NEWS",
            "NEWS.txt",
            "RELEASES.md",
            "RELEASE_NOTES.md",
        ],
        ["packages/a/CHANGELOG.md", "docs/CHANGELOG.md", "CHANGELOG.json", "CHANGELOG/v1.md", "NEWSLETTER.md"],
    ),
    "changelog_dir": (
        [
            "changelog.d/123.fix.md",
            ".changes/v1.2.0.md",
            ".changes/unreleased/Added-20260508-220000.yaml",
            "newsfragments/42.bugfix",
            "changelog/pending/20260101--cli--fix.yaml",
            "changelog/1234-fix-login.md",
            "changelog/1234.feature.md",
        ],
        [
            "CHANGELOG.md",
            "docs/changelog/1.md",
            "changes/x.md",
            # a changelog split by version, or a page about it
            "CHANGELOG/CHANGELOG-1.30.md",
            "changelogs/CHANGELOG.0.10.md",
            "changelog/v1.2.md",
            "CHANGELOG/26.10.md",
            "changelog/v0-v9.md",
            "changelog/v0.json",
            "changelog/README.md",
            "changelog/index.html",
        ],
    ),
    "docs_site": (
        [
            "mint.json",
            "docs/mint.json",
            "docusaurus.config.js",
            "website/docusaurus.config.ts",
            "mkdocs.yml",
            "docs/mkdocs.yaml",
            "docs/conf.py",
            "doc/source/conf.py",
            "packages/a/docs/conf.py",
            ".readthedocs.yaml",
            "docs/.vitepress/config.mts",
            "typedoc.json",
            "book.toml",
            "guide/book.toml",
        ],
        [
            "conf.py",
            "src/conf.py",
            "examples/docs/mkdocs.yml",
            "templates/docusaurus/docusaurus.config.js",
            "docs.json",
            "mkdocs.md",
            "a/b/c/mkdocs.yml",
        ],
    ),
    "docs_json": (["docs.json", "docs/docs.json", "apps/docs/docs.json"], ["src/docs.json", "api/docs.json"]),
    "docs_other": (
        ["antora.yml", "docs/antora-playbook.yml", "docfx.json", "Doxyfile", "rspress.config.ts", "book/_toc.yml"],
        ["antora.md", "docfx.md", "doxygen.css"],
    ),
    "commit_convention": (
        [
            "commitlint.config.js",
            "commitlint.config.ts",
            ".commitlintrc",
            ".commitlintrc.json",
            "frontend/commitlint.config.ts",
        ],
        # a commitizen config alone checks nothing
        ["commitlint.md", ".cz-config.js", "a/b/c/.commitlintrc", ".cz.toml", "cz.json", ".czrc", ".cz.json"],
    ),
    "changesets": ([".changeset/config.json"], [".changeset/blue-cats-dance.md", "changeset/config.json"]),
    "lint_staged_config": (
        [".lintstagedrc", ".lintstagedrc.json", "lint-staged.config.mjs", "web/lint-staged.config.js"],
        ["lint-staged.md", ".lintstagedrc.bak.old"],
    ),
}

# Shipped material: matched by the rule but not counted.
SHIPPED = [
    "templates/next/CLAUDE.md",
    "examples/basic/AGENTS.md",
    "test/fixtures/.mcp.json",
    "evals/task-1/.claude/skills/a/SKILL.md",
    "private-demos/AGENTS.md",
    "node_modules/pkg/CLAUDE.md",
    "packages/create-app/template/.cursor/rules/a.mdc",
    "starter-kits/quickstart/AGENTS.md",
]
NOT_SHIPPED = ["packages/latest/AGENTS.md", "testing/AGENTS.md", "contest/CLAUDE.md", "apps/attestations/AGENTS.md"]

# Workflow text (lowercased first): agent, texts that call it, near misses
CI = {
    "claude": (
        [
            "uses: anthropics/claude-code-action@v1",
            "run: npm i -g @anthropic-ai/claude-code",
            "run: claude -p 'fix the build'",
            "claude_code_oauth_token: ${{ secrets.t }}",
        ],
        ["anthropic_api_key: ${{ secrets.k }}", "run: claude --version"],
    ),
    "codex": (["uses: openai/codex-action@v1", "run: codex exec 'triage'", "npx @openai/codex"], ["run: codex login"]),
    "gemini": (
        ["uses: google-github-actions/run-gemini-cli@v0", "run: gemini -p 'review'"],
        ["gemini_api_key: ${{ secrets.k }}"],
    ),
    "copilot": (["uses: github/gh-aw/actions@v1", "run: copilot -p 'fix'"], ["copilot-setup-steps:"]),
    "cursor": (["run: cursor-agent -p 'fix'", "curl https://cursor.com/install | bash"], ["run: cursor ide"]),
    "opencode": (["uses: sst/opencode/github@latest", "run: opencode run 'fix'"], ["cat opencode.json"]),
    "amp": (["npm i -g @sourcegraph/amp", "run: amp -x 'fix'"], ["run: amp --version"]),
    "aider": (["pip install aider-chat", "run: aider --yes"], ["run: raider --x", "run: aider"]),
    "openhands": (["uses: all-hands-ai/openhands-resolver@v1"], ["all-hands meeting"]),
    "droid": (["uses: factory-ai/droid-action@v1", "run: droid exec 'fix'"], ["run: android exec"]),
    "goose": (["uses: block/goose@v1", "run: goose run -t 'fix'"], ["run: mongoose run"]),
    "warp": (["uses: warpdotdev/oz-agent-action@v1", "run: oz-agent"], ["uses: warpdotdev/warp@v1"]),
    "devin": (["curl https://api.devin.ai/v1/sessions"], ["see devin.ai"]),
    "jules": (["uses: google-labs-code/jules-action@v1"], ["echo jules"]),
}

# Commit identities, "name <email>" lowercased: agent, identities, near misses. The near misses are
# people: a person on an agent vendor's domain, or a person whose name is an agent's.
IDENTITY = {
    "claude": (
        ["claude <noreply@anthropic.com>", "claude[bot] <1+claude[bot]@users.noreply.github.com>"],
        ["jane doe <jane-example@anthropic.com>"],
    ),
    "cursor": (
        ["cursor agent <cursoragent@cursor.com>", "cursor[bot] <x-example@users.noreply.github.com>"],
        ["sam example <sam-example@cursor.com>"],
    ),
    "copilot": (
        ["copilot <198982749+copilot@users.noreply.github.com>", "copilot-swe-agent[bot] <x@example.com>"],
        ["pat example <pat-example@github.com>"],
    ),
    "codex": (["codex <codex@openai.com>", "gpt-5 <noreply@openai.com>"], ["alex example <alex-example@openai.com>"]),
    "gemini": (["gemini-cli[bot] <x@example.com>", "gemini <x@example.com>"], ["gemini smith <g@example.com>"]),
    "jules": (["google-labs-jules[bot] <x@example.com>"], ["jules verne <jules@example.com>"]),
    "amp": (["amp <amp@ampcode.com>"], ["dev example <dev-example@ampcode.com>"]),
    "devin": (["devin-ai-integration[bot] <x@example.com>"], ["devin example <devin@example.com>"]),
    "aider": (["jane doe (aider) <jane@example.com>", "aider <x@example.com>"], ["aiden <aiden@example.com>"]),
    "opencode": (["opencode <noreply@opencode.ai>"], ["dev example <dev-example@opencode.ai>"]),
    "droid": (["factory-droid[bot] <x@example.com>", "droid <droid@factory.ai>"], ["android dev <a@example.com>"]),
    "openhands": (["openhands <openhands@all-hands.dev>"], ["open hands <oh@example.com>"]),
    "warp": (["oz <agent@warp.dev>"], ["dev example <dev-example@warp.dev>"]),
    "junie": (["junie <junie@jetbrains.com>"], ["dev example <dev-example@jetbrains.com>"]),
    "kiro": (["kiro agent <x@example.com>", "kiro <noreply@kiro.dev>"], ["kirov <k@example.com>"]),
    "windsurf": (["cascade <x@example.com>"], ["windsurfer <w@example.com>"]),
    "lovable": (["lovable-dev[bot] <x@example.com>"], ["lovable <l@example.com>"]),
    "v0": (["v0[bot] <x@example.com>"], ["v01 <v@example.com>"]),
    "codegen": (["codegen-sh[bot] <x@example.com>"], ["codegen <c@example.com>"]),
    "sweep": (["sweep-ai[bot] <x@example.com>"], ["sweep <s@example.com>"]),
}

# Commit bodies, lowercased: agent, bodies, near misses
BODY = {
    "claude": (["fix\n\n🤖 generated with [claude code](https://claude.com/claude-code)"], ["generated with claude"]),
    "amp": (["fix\n\namp-thread-id: https://ampcode.com/threads/t-1"], ["see amp-thread-id: t-1"]),
    "codex": (["generated with codex"], ["generated with codecov"]),
    "cursor": (["made with cursor", "generated with [cursor](https://cursor.com)"], ["made using cursor"]),
    "opencode": (["generated with [opencode](https://opencode.ai)"], ["generated with open code"]),
    "copilot": (["generated with github copilot"], ["generated with copilot"]),
    "gemini": (["generated with gemini cli"], ["generated by gemini"]),
    "droid": (["generated with droid"], ["generated by droid"]),
    "warp": (["generated with warp"], ["generated by warp"]),
}


# What a workflow runs (lowercased first; matched on scan.workflow_commands): check, texts that count, near misses
CHECKS = {
    "tests": (
        [
            "run: pnpm test",
            "run: uv run pytest -q",
            "run: go test ./...",
            "run: cargo nextest run",
            "run: npm run test:unit",
            "rake test",
            "bazel test //...",
            "swift test",
            "pnpm --filter x test",
            "pnpm coverage",
            "pnpm e2e:ci",
            "make test-unit",
            "mise run test",
            # a package manager, then what may stand before the script: workspace, -C dir, --cwd, --dir, --prefix
            "yarn workspace x test",
            "pnpm -c packages/x test",
            "npm --prefix web run test:ci",
            "pnpm --dir a test",
            "pnpm --cwd a test",
            # a script whose name holds the word among parts split by : or -
            "bun run check:test",
            "pnpm run test:unit",
            "pnpm ci:test-e2e",
            "npm test",
            # a turbo task among several
            "turbo run lint test --no-update-notifier",
            "turbo run test",
        ],
        [
            "run: echo latest",
            "run: echo contest",
            "uses: actions/checkout@v4",
            "run: pnpm build",
            "make latest-build",
            "make build",
            "make contest",
            "yarn workspace x build",
            "pnpm testing",
            "pnpm install",
            "pnpm test:types",
            "turbo run build --filter=@acme/test-utils",
        ],
    ),
    "lint": (
        [
            "run: pnpm lint",
            "run: ruff check .",
            "uses: pre-commit/action@v3",
            "run: cargo clippy",
            "run: biome ci .",
            "make lint_package",
            "nx run-many --target=lint",
            "uses: astral-sh/ruff-action@v3",
            "pnpm format:check",
            "npx ultracite check",
            "bun run check:lint",
            "pnpm run check-format",
            "turbo run lint formatting",
            "turbo run lint test",
            # the word alone in a command
            "clojure -m:lint",
            "deno task lint",
            "node tools/lint.js",
            "pnpm nx affected --targets=lint,test",
        ],
        [
            "run: pnpm build",
            "run: ruff --version",
            "run: echo splinter",
            "make build",
            "pnpm run reformat",
            "pnpm build --no-lint",
            "npx commitlint",
            "mise run check",
            "echo information",
        ],
    ),
    # test:types is a type check and no more
    "types": (
        [
            "run: pnpm exec tsc --noemit",
            "run: mypy src",
            "run: pnpm typecheck",
            "run: cargo check --all",
            "pnpm test:types",
            "pnpm typescript:check",
            "vue-tsc --noemit",
        ],
        ["run: echo tsconfig", "run: pnpm build", "run: echo prototype"],
    ),
}

# Security tools a workflow calls (lowercased first): tool, texts that count, near misses
SCANNERS = {
    # init or analyze: upload-sarif alone sends the results of another tool
    "codeql": (
        ["uses: github/codeql-action/analyze@v3", "uses: github/codeql-action/init@v3"],
        ["uses: github/super-linter@v5", "uses: github/codeql-action/upload-sarif@v3"],
    ),
    "semgrep": (["run: semgrep scan --config auto", "uses: semgrep/semgrep-action@v1"], ["run: echo grep"]),
    "sonar": (
        ["uses: sonarsource/sonarqube-scan-action@v5", "url: https://sonarcloud.io", "run: sonar-scanner"],
        ["run: echo sonata"],
    ),
    "snyk": (
        ["uses: snyk/actions/node@master", "run: snyk test --severity-threshold=high"],
        ["run: snyk auth", "run: echo snykes"],
    ),
    "code_lint": (["run: bandit -r src", "run: gosec ./...", "run: brakeman"], ["run: echo bandits"]),
    "trivy": (
        ["uses: aquasecurity/trivy-action@0.28.0", "run: trivy fs ."],
        ["run: trivy --version", "run: echo trivial"],
    ),
    "grype": (["uses: anchore/scan-action@v6", "run: grype dir:."], ["uses: anchore/sbom-action@v0"]),
    "osv": (
        ["uses: google/osv-scanner-action/osv-scanner-action@v2", "run: osv-scanner --lockfile=a"],
        ["run: echo osv"],
    ),
    "govulncheck": (["run: govulncheck ./..."], ["run: go vet ./..."]),
    "cargo_audit": (
        [
            "run: cargo audit",
            "run: cargo-deny check",
            "uses: rustsec/audit-check@v2",
            "uses: embarkstudios/cargo-deny-action@v2",
        ],
        ["run: cargo build", "run: cargo test", "run: cargo auditable build"],
    ),
    "pip_audit": (["run: pip-audit -r requirements.txt", "run: safety check"], ["run: pip install pip-tools"]),
    "npm_audit": (
        ["run: npm audit --audit-level=high", "run: pnpm audit", "run: npx audit-ci"],
        ["run: npm install", "run: echo audit"],
    ),
    "dependency_review": (["uses: actions/dependency-review-action@v4"], ["uses: actions/checkout@v4"]),
    "socket": (
        [
            "uses: socketdev/action@v1",
            "uses: socketdev/socket-registry-firewall@v1",
            "run: npx @socketsecurity/cli scan",
        ],
        ["run: npm install socket.io", "socket-security[bot]"],
    ),
    "gitleaks": (["uses: gitleaks/gitleaks-action@v2", "run: gitleaks detect"], ["run: echo leaks"]),
    "trufflehog": (["uses: trufflesecurity/trufflehog@main"], ["uses: trufflesecurity/other@v1"]),
    "gitguardian": (["uses: gitguardian/ggshield-action@v1", "run: ggshield secret scan ci"], ["run: echo guardian"]),
    "scorecard": (["uses: ossf/scorecard-action@v2.4.0"], ["uses: ossf/other-action@v1"]),
    "zizmor": (
        ["uses: zizmorcore/zizmor-action@v0", "run: uvx zizmor .", "zizmor"],
        ["run: echo zig", "run: echo hizzmorx", "echo zizmorcore"],
    ),
    "actionlint": (["run: actionlint", "uses: rhysd/actionlint@v1"], ["run: echo action lint"]),
    "harden_runner": (["uses: step-security/harden-runner@v2"], ["uses: step-security/secure-repo@v2"]),
}

# Security as a whole in what a workflow runs (lowercased, comments dropped): what counts, near misses
SUPPLY = {
    "provenance": (
        [
            "actions/attest-build-provenance@v2",
            "actions/attest@v1",
            "npm publish --provenance --access public",
            "pnpm -r publish --provenance",
            "cosign sign --yes ghcr.io/a/b@sha256:x",
            "cosign sign-blob --yes a.json",
            "cosign attest --type spdxjson",
            "slsa-framework/slsa-github-generator/.github/workflows/x.yml@v2",
        ],
        [
            "docker buildx build --provenance=false .",
            "--provenance false",
            "sigstore/cosign-installer@v3",
            "cosign verify ghcr.io/a/b",
            "actions/attest-sbom-x@v1",
            "echo provenance",
        ],
    ),
    "sbom": (
        [
            "anchore/sbom-action@v0",
            "anchore/sbom-action/download-syft@v0",
            "syft dir:. -o spdx-json",
            "cyclonedx-npm --output-file a.xml",
            "cargo cyclonedx --format xml",
            "docker buildx build --sbom=true .",
            "type=sbom,generator=x",
            "actions/attest-sbom@v1",
            "trivy image -f spdx-json a",
        ],
        [
            "docker buildx build --provenance=false --sbom=false .",
            "--sbom false",
            "spdx-license-identifier: mit",
            "echo sbom",
            "syftly",
            "**/*.spdx",
        ],
    ),
    "fuzz": (
        [
            "google/clusterfuzzlite/actions/run_fuzzers@v1",
            "google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@master",
            "cargo +nightly fuzz run parser -- -max_total_time=30",
            "cargo fuzz build -s none",
            "go test -run '^$' -fuzz fuzzparse ./pkg",
            "uv run --with atheris python fuzz/fuzz_parse.py",
            "pip install atheris",
            "jazzer --cp=a",
        ],
        ["cargo fuzzy", "cargo install cargo-fuzz", "go test ./...", "echo fuzz", "go test -fuzzy x"],
    ),
    "audit": (
        [
            "bundle exec bundle-audit check",
            "bundler-audit",
            "composer audit --no-dev",
            "mix deps.audit",
            "mix hex.audit",
            "dotnet list package --vulnerable",
            "docker/scout-action@v1",
            "docker scout cves img",
            "snyk container test a/b",
            "cargo audit",
            "rustsec/audit-check@v2",
            "embarkstudios/cargo-deny-action@v2",
            "cargo deny check",
            "cargo deny check advisories",
            "cargo deny --manifest-path a/cargo.toml check advisories",
            "cargo deny check --hide-inclusion-graph advisories sources",
            "cargo deny check -a x advisories",
            "a\ncargo deny check\nb",
            "pip-audit -r requirements.txt",
            "safety check -r r.txt",
            "uv run safety scan",
            "echo x\n  safety check",
        ],
        [
            "cargo deny check licenses",
            "cargo deny --locked --all-features check bans licenses sources",
            "a\ncargo deny check licenses\nb",
            "cargo auditable build",
            "composer install",
            "mix deps.get",
            "dotnet list package",
            "docker scout quickview",
            "snyk container auth",
            "automated upgrade-safety check",
            "print('the artifact failed the safety check')",
            "echo composer audited",
        ],
    ),
    "secrets": (
        [
            "detect-secrets scan --baseline .secrets.baseline",
            "detect-secrets-hook scan",
            "detect-secrets audit x",
            "npx secretlint '**/*'",
        ],
        ["pip install detect-secrets", "echo secrets", "secretlintrc"],
    ),
}
# The same, set as an input of an action or an environment variable (matched on the workflow's text)
SUPPLY_INPUTS = {
    "provenance": (
        [
            "          provenance: true",
            "  provenance: mode=max",
            "    attestations: true",
            '  npm_config_provenance: "true"',
            "- provenance: true",
        ],
        [
            "  provenance: false",
            "  attestations: false",
            "  npm_config_provenance: false",
            "name: provenance: true",
            "  provenance: mode=min",
        ],
    ),
    "sbom": (["  sbom: true", "    sbom: 'true'"], ["  sbom: false", "  sbom-format: true", "  generate-sbom: false"]),
}

# How a workflow that calls an agent fences it (lowercased first): fence, texts that count, near misses
# What a workflow runs, as scan.workflow_commands gives it (an action's `uses` value starts a line): the readers of
# practices read from workflows. An action kept on a person's account is written here under a made-up owner: only its
# repo name is matched.
OPS_RUN = {
    "cache": (
        ["actions/cache@v4", "actions/cache/restore@v4", "acme/rust-cache@v2", "mozilla-actions/sccache-action@v0.0.9"],
        ["actions/checkout@v4", "run: cache clean", "acme/cache-cleanup@v1", "actions/setup-node@v4"],
    ),
    "coverage": (
        [
            "codecov/codecov-action@v5",
            "coverallsapp/github-action@v2",
            "pnpm vitest run --coverage",
            "pytest --cov=src --cov-report=xml",
            "go test -coverprofile=c.out ./...",
            "go test -cover ./...",
            "cargo llvm-cov --lcov",
            "cargo tarpaulin --out xml",
            "nyc mocha",
            "c8 node --test",
            "coverage run -m pytest",
            "mix test --cover",
            "pnpm test:coverage",
            "make coverage",
        ],
        ["codecov/test-results-action@v1", "pnpm test", "echo discover", "go test ./...", "cat coverage.txt"],
    ),
    "paths_action": (
        ["acme/paths-filter@v3", "tj-actions/changed-files@v46", "step-security/changed-files@v45"],
        ["actions/checkout@v4", "run: git diff --name-only", "acme/paths-filter-docs"],
    ),
    "affected": (
        ["npx nx affected -t test", "pnpm nx run-many -t lint --affected", "turbo run build --affected", "moon ci"],
        ["npx nx run-many -t test", "turbo run build", "echo affected"],
    ),
    "affected_filter": (
        ['pnpm --filter "...[origin/main]" test', "turbo run test --filter=[HEAD^1]"],
        ["pnpm --filter web test", "turbo run build --filter=./apps/*"],
    ),
    "spellcheck": (
        [
            "crate-ci/typos@v1.29.0",
            "codespell-project/actions-codespell@v2",
            "streetsidesoftware/cspell-action@v6",
            "codespell --skip=*.lock",
            "typos",
            "npx cspell lint .",
            "pre-commit run codespell --all-files",
        ],
        ["echo fix typos", "cat typos.toml", "pip install codespell", "cspell.json"],
    ),
    "actionlint": (["actionlint -color", "acme/actionlint@v1"], ["echo action lint"]),
    "app_token": (
        ["actions/create-github-app-token@v2", "acme/github-app-token@v1", "acme/action-github-app-token@v1"],
        ["actions/checkout@v4", "echo github-app-token", "acme/github-token@v1"],
    ),
    "release": (
        [
            "gh release create v1.0.0 dist/*",
            "acme/action-gh-release@v2",
            "acme/release-action@v1",
            "goreleaser/goreleaser-action@v6",
            "goreleaser release --clean",
            "googleapis/release-please-action@v4",
            "npx semantic-release",
            "changesets/action@v1",
            "actions/create-release@v1",
        ],
        ["gh release upload v1 a.tgz", "gh release view", "echo release", "release-drafter/release-drafter@v6"],
    ),
    "release_draft": (["release-drafter/release-drafter@v6"], ["gh release create v1"]),
    "image_push": (
        [
            "docker push ghcr.io/acme/app:latest",
            "docker buildx build --platform linux/amd64 --push -t x .",
            "docker buildx bake --push",
            "docker buildx imagetools create -t x a b",
            "docker compose push",
            "ko build ./cmd/app",
            "podman push x",
        ],
        ["docker build -t x .", "docker buildx build --load -t x .", "docker pull x", "ko build --local ./cmd/app"],
    ),
    "image_build": (
        ["docker/build-push-action@v6", "docker build -t x .", "docker buildx bake", "docker compose build"],
        ["docker run x", "docker pull x", "docker/setup-buildx-action@v3"],
    ),
    "multi_arch": (
        [
            "docker/setup-qemu-action@v3",
            "docker buildx build --platform linux/amd64,linux/arm64 .",
            "docker buildx bake --set *.platform=linux/arm64",
            "docker buildx imagetools create -t x a b",
        ],
        [
            "docker buildx build --platform linux/amd64 .",
            "pip download --platform manylinux2014_aarch64 x",
            "cargo build --target aarch64-unknown-linux-gnu",
        ],
    ),
    "deploy": (
        [
            "npx wrangler deploy",
            "wrangler pages deploy dist",
            "cloudflare/wrangler-action@v3",
            "flyctl deploy --remote-only",
            "kubectl apply -f k8s/",
            "helm upgrade --install app ./chart",
            "aws ecs update-service --cluster c",
            "aws s3 sync dist s3://bucket",
            "aws lambda update-function-code --function-name f",
            "gcloud run deploy app --image x",
            "vercel deploy --prebuilt --prod",
            "npx vercel --prod --token x",
            "netlify deploy --prod",
            "firebase deploy --only hosting",
            "npx serverless deploy",
            "npx cdk deploy --all",
            "npx sst deploy --stage prod",
            "terraform apply -auto-approve",
            "pulumi up --yes",
            "aws-actions/amazon-ecs-deploy-task-definition@v2",
            "google-github-actions/deploy-cloudrun@v2",
            "azure/webapps-deploy@v3",
            "acme/vercel-action@v25",
        ],
        [
            "aws-actions/configure-aws-credentials@v4",
            "google-github-actions/auth@v2",
            "terraform plan",
            "pulumi preview",
            "vercel pull --yes",
            "kubectl get pods",
            "helm lint chart",
            "aws s3 ls",
            "echo deploy",
            "pnpm deploy",
            "actions/deploy-pages@v4",
            "npx wrangler deploy --dry-run --outdir dist",
            "helm upgrade --install app ./chart --dry-run",
            "aws s3 sync dist s3://bucket --dryrun",
        ],
    ),
    "deploy_k8s": (
        ["kubectl -n prod apply -f k8s/", "helm upgrade app ./chart", "azure/k8s-deploy@v5"],
        ["wrangler deploy", "kubectl apply --dry-run=client -f k8s/"],
    ),
    "deploy_s3": (["aws s3 sync dist s3://bucket --delete"], ["aws s3 cp a s3://b", "kubectl apply -f x"]),
    "deploy_other": (["firebase deploy", "terraform apply"], ["kubectl apply -f x", "aws s3 sync a s3://b"]),
    "deploy_pages": (
        ["actions/deploy-pages@v4", "acme/actions-gh-pages@v4", "acme/github-pages-deploy-action@v4"],
        ["actions/upload-pages-artifact@v3", "actions/configure-pages@v5"],
    ),
    "cloud_login": (
        ["aws-actions/configure-aws-credentials@v4", "google-github-actions/auth@v2", "azure/login@v2"],
        ["aws-actions/amazon-ecr-login@v2", "docker/login-action@v3"],
    ),
    "publish": (
        [
            "npm publish --provenance --access public",
            "pnpm publish --no-git-checks",
            "pnpm -r publish --access public",
            "pnpm --filter=core publish",
            "yarn npm publish",
            "yarn publish",
            "bun publish",
            "cargo publish -p core",
            "uv publish",
            "poetry publish --build",
            "twine upload dist/*",
            "gem push pkg/x.gem",
            "dotnet nuget push *.nupkg",
            "npx lerna publish from-package",
            "pnpm changeset publish",
            "pypa/gh-action-pypi-publish@release/v1",
            "mvn -B deploy",
            "./gradlew publishallpublicationstomavencentral",
            "./gradlew :lib:publish",
        ],
        [
            "npm publish --dry-run",
            "cargo publish --dry-run",
            "npm pack",
            "echo publish",
            "./gradlew publishtomavenlocal",
            "pnpm build",
            "mvn -B verify",
            "pnpm run publish-script",
            "npm run publish:docs",
        ],
    ),
    "publish_script": (
        [
            "pnpm run publish-script",
            "yarn publish:canary",
            "make publish",
            "pnpm exec tsx ./internal/scripts/publish-new.ts --bump minor",
            "./scripts/publish.sh",
        ],
        ["npm publish", "echo published", "cat publishing.md", "pnpm build"],
    ),
    "deploy_script": (
        ["pnpm exec tsx internal/scripts/deploy-dotcom.ts", "make deploy-prod", "npm run deploy", "bash deploy.sh"],
        ["echo deploy", "wrangler deploy", "cat deployment.md", "pnpm build"],
    ),
    "stale": (["actions/stale@v9"], ["actions/labeler@v5", "acme/stale@v1"]),
    "labeler": (["actions/labeler@v5"], ["actions/stale@v9", "acme/labeler@v1"]),
    "title_check": (
        [
            "acme/action-semantic-pull-request@v5",
            "npx commitlint --from origin/main",
            "acme/commitlint-github-action@v6",
        ],
        ["actions/checkout@v4", "echo semantic"],
    ),
}
OPS_TEXT = {
    "concurrency": (
        [
            "concurrency:\n  group: x\n  cancel-in-progress: true\n",
            "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
            "concurrency: { group: x, cancel-in-progress: true }",
        ],
        [
            "concurrency:\n  group: x\n  cancel-in-progress: false\n",
            "  cancel-in-progress: 'false'",
            "concurrency: { group: x, cancel-in-progress: false }",
            "concurrency: x",
        ],
    ),
    "timeouts": (["    timeout-minutes: 30", "      - timeout-minutes: 5"], ["    timeout: 30", "# timeout-minutes"]),
    "cache_docker": (["          cache-from: type=gha", "docker buildx build --cache-to type=gha ."], ["cache: npm"]),
}

FENCE = {
    "tools": (
        ["allowed_tools: bash(git:*)", 'claude_args: --allowedtools "read"', "disallowed-tools: bash"],
        ["tools: all", "allowed_users: dev"],
    ),
    # the list lets any shell command through: bare bash or bash(*), inline or as an item of a block list.
    # A bash(pattern) does not count, and a disallowed list does not either
    "bash": (
        [
            "allowed_tools: bash",
            'allowed_tools: "bash"',
            "allowed_tools: bash(*)",
            "allowed_tools: read,bash",
            "allowed_tools: bash, read",
            'allowed_tools: ["read", "bash"]',
            'allowed_tools: "bash(*),read"',
            "allowed_tools: bash(git:*),bash",
            "claude_args: --allowedtools bash",
            'claude_args: --allowedtools "bash,read"',
            "allowed-tools: bash",
            "allowed_tools:\n  - read\n  - bash\n",
            "allowed_tools: |\n  read\n  bash\n",
        ],
        [
            "allowed_tools: bash(git:*)",
            "allowed_tools: bash(ls)",
            "allowed_tools:\n  - bash(git:*)\n  - read\n",
            "disallowed_tools: bash",
            "disallowed_tools:\n  - bash\n",
            "allowed_tools: bashful",
            "allowed_tools: read",
            "allowed_tools: read\nprompt: use bash\n",
            "allowed_tools:\n  - read\nprompt: bash\n",
            "- bash\n",
            "run: bash script.sh",
        ],
    ),
    # a named bot; "*" is open
    "bots": (
        ["allowed_bots: 'dependabot[bot]'", "allowed_bots: dependabot"],
        ["bots: all", 'allowed_bots: "*"', "allowed_bots: *", "allowed_bots: ''", "allowed_bots:"],
    ),
    "assoc": (["if: github.event.comment.author_association == 'member'"], ["if: github.actor == 'dev'"]),
    "open": (
        [
            "allowed_non_write_users: '*'",
            "allowed_non_write_users: *",
            'allow-users: "*"',
            'allowed_bots: "*"',
            "allowed_bots: *",
        ],
        ["allowed_non_write_users: ''", "allow-users: dev"],
    ),
    "skip": (
        [
            "claude_args: --dangerously-skip-permissions",
            "run: gemini --yolo",
            "sandbox: danger-full-access",
            "permission-mode: bypasspermissions",
            "run: codex --dangerously-bypass-approvals-and-sandbox",
        ],
        ["run: echo yolo-mode", "permission-mode: acceptedits"],
    ),
    "review": (
        ["uses: anthropics/claude-code-security-review@main", "run: claude -p '/security-review'"],
        ["run: echo security-review", "run: echo a security review is due"],
    ),
}

# A wait before a new package version may be installed, per file (lowercased first):
# manager, file, texts that count, near misses. A zero or a fixed date is not a wait.
COOL = {
    "pnpm": {
        "pnpm-workspace.yaml": (
            ["minimumreleaseage: 1440", "packages:\n  - a\nminimumreleaseage: '4320'"],
            ["minimumreleaseage: 0", "minimumreleaseageexclude:\n  - a", "# minimumreleaseage: 1440"],
        ),
        ".npmrc": (["minimum-release-age=1440"], ["minimum-release-age=0", "; minimum-release-age=1440"]),
        "package.json": (['"minimumreleaseage": 1440'], ['"minimumreleaseage": 0']),
    },
    "npm": {".npmrc": (["min-release-age=7"], ["min-release-age=0", "registry=https://example.com"])},
    "yarn": {
        ".yarnrc.yml": (
            ["npmminimalagegate: 3d", "npmminimalagegate: 4320"],
            ["# npmminimalagegate: 3d", "nodelinker: node-modules", "npmminimalagegate: 0", "npmminimalagegate: '0'"],
        )
    },
    "bun": {
        "bunfig.toml": (["[install]\nminimumreleaseage = 604800"], ["minimumreleaseage = 0", "[install]\nexact = true"])
    },
    "uv": {
        "pyproject.toml": (
            ['[tool.uv]\nexclude-newer = "7 days"', 'exclude-newer = "1 week"', 'exclude-newer = "p7d"'],
            ['exclude-newer = "2026-01-01t00:00:00z"', 'exclude-newer = "2026-01-01"', '# exclude-newer = "7 days"'],
        ),
        "uv.toml": (['exclude-newer = "7 days"'], ['exclude-newer = "2026-01-01t00:00:00z"']),
    },
    "dependabot": {
        "dependabot": (
            [
                "updates:\n  - package-ecosystem: npm\n    cooldown:\n      default-days: 7",
                "updates:\n  - cooldown:\n      default-days: 3\n    package-ecosystem: npm",
            ],
            ["updates:\n  - package-ecosystem: npm", "# cooldown:\n", "# - cooldown:\n"],
        )
    },
    "renovate": {
        "renovate": (
            [
                '"minimumreleaseage": "3 days"',
                '"stabilitydays": 3',
                '"extends": [":minimumreleaseage(7 days)"]',
                '"extends": ["security:minimumreleaseagenpm"]',
            ],
            [
                '"extends": ["config:recommended"]',
                '"minimumreleaseage": "0 days"',
                '"minimumreleaseage": null',
                '// "minimumreleaseage": "3 days"',
                '  // "minimumreleaseage": "3 days"',
                '"stabilitydays": 0',
                '"extends": [":minimumreleaseage(0 days)"]',
            ],
        )
    },
}

# Other guards of a package manager's file (lowercased first): guard, file, texts that count, near misses
GUARDS = {
    "trust_policy": {
        "pnpm-workspace.yaml": (
            ["trustpolicy: no-downgrade", "trustpolicy: 'no-downgrade'"],
            ["trustpolicy: off", "# trustpolicy: no-downgrade"],
        )
    },
    "no_scripts": {
        ".npmrc": (["ignore-scripts=true", "ignore-scripts = true"], ["ignore-scripts=false"]),
        ".yarnrc.yml": (["enablescripts: false"], ["enablescripts: true"]),
        "bunfig.toml": (["ignorescripts = true"], ["ignorescripts = false"]),
    },
}

# Tools named in the root package.json: tool, dependency name, near misses
PACKAGE = {
    "oxlint": ("oxlint", ['"lint": "oxlint ."', '"oxlint-tsgolint-docs": "1"']),
    "oxfmt": ("oxfmt", ['"fmt": "oxfmt ."']),
    "biome": ("@biomejs/biome", ['"lint": "biome check ."', '"biome": "1"']),
    "eslint": ("eslint", ['"eslint-plugin-react": "^7"', '"lint": "eslint ."']),
    "prettier": ("prettier", ['"prettier-plugin-tailwindcss": "^0.6"']),
    "knip": ("knip", ['"deadcode": "knip"']),
    "tsgo": ("@typescript/native-preview", ['"typecheck": "tsgo"']),
    "tsgolint": ("oxlint-tsgolint", ['"oxlint": "^1"']),
    "typescript": ("typescript", ['"typescript-eslint": "^8"', '"@types/node": "^22"']),
    "husky": ("husky", ['"prepare": "husky"', '"husky-init": "1"']),
    "simple_git_hooks": ("simple-git-hooks", ['"prepare": "simple-git-hooks"', '"simple-git-hooks-x": "1"']),
    "lefthook": ("lefthook", ['"prepare": "lefthook install"']),
    "lint_staged": ("lint-staged", ['"lint-staged-docs": "1"']),
    "vitest": ("vitest", ['"vitest-fetch-mock": "1"', '"test": "vitest"']),
    "jest": ("jest", ['"@types/jest": "29"', '"jest-extended": "4"']),
    "playwright": ("@playwright/test", ['"playwright": "1"', '"e2e": "playwright test"']),
    "cypress": ("cypress", ['"cypress-axe": "1"']),
}

# Tools named in the root pyproject.toml (lowercased first): tool, texts that count, near misses
PYPROJECT = {
    "ruff": (["[tool.ruff]", "[tool.ruff.lint]", 'dev = ["ruff>=0.5"]'], ["[tool.black]", '"truffle>=1"']),
    "mypy": (
        ["[tool.mypy]", '"mypy>=1.0"', '"mypy"', '"mypy[reports]>=1"'],
        ["[tool.black]", '"unittest2>=1"', '"mypy-primer>=1"', '"mypy-extensions>=1"'],
    ),
    "pyright": (
        ["[tool.pyright]", "[tool.basedpyright]", '"pyright>=1.1"', '"basedpyright"'],
        ["[tool.pylint]", '"pyrightconfig"'],
    ),
    "ty": (["[tool.ty]", "[tool.ty.rules]", '"ty>=0.0.1"', '"ty"'], ["[tool.typer]", '"typing-extensions>=4"']),
    "pyrefly": (["[tool.pyrefly]", '"pyrefly>=0.1"'], ["[tool.pyre]"]),
    "pytest": (["[tool.pytest.ini_options]", '"pytest>=8"', '"pytest-cov"'], ["[tool.poetry]", '"unittest2"']),
}

# What an agent hook runs (lowercased first): check, commands that count, near misses
HOOK = {
    "format": (
        ["prettier --write $file", "./format.sh", "gofmt -w .", "post-edit-format.js", "reformat x"],
        ["echo done", "pnpm build", "information", "--format json", "--format=json"],
    ),
    "lint": (["pnpm lint --fix", "eslint --fix", "ruff check ."], ["echo done", "afplay glass.aiff"]),
    "types": (["pnpm exec tsc --noemit", "mypy .", "pyright"], ["echo done", "cat tsconfig.json"]),
    "tests": (
        ["pnpm test", "vitest run", "pytest -q", "bun test"],
        ["echo latest", "./contest.sh", "test -f package.json", "[ -f x ] && test -d y"],
    ),
    "check": (["pnpm check", "cargo check", "./checks.sh"], ["echo checkout", "git checkout main"]),
}

# What the git hooks run (lowercased first, then cleaned with HOOK_NOISE: see clean_hook): job, texts that count,
# near misses
GIT_HOOK = {
    "lint": (
        ["- id: ruff", "run: pnpm exec eslint --fix {staged_files}", "- id: prettier", "biome check --write"],
        [
            "- id: check-added-large-files",
            "- id: end-of-file-fixer",
            "run: echo hi",
            "copyright: 2024",
            "# lint the code",
            "npx commitlint --edit $1",
        ],
    ),
    "types": (
        ["run: tsc --noemit", "- id: mypy", "run: pnpm typecheck", "- id: pyright", "- id: ty check"],
        ["- id: ruff", "- id: check-json", "copyright", "perplexity check", "- id: perplexity check", "# tsc is slow"],
    ),
    "tests": (
        [
            "run: pnpm test",
            "run: pytest -x",
            "run: go test ./...",
            "run: cargo test",
            "entry: uv run pytest",
            "pnpm exec vitest related",
            "bunx vitest related --run",
            "entry: pytest",
        ],
        [
            "- id: check-yaml",
            "run: echo latest",
            "args: [--pytest-test-first]",
            'additional_dependencies: ["pytest"]',
            "- id: pytest-check",
            "# pytest is slow",
        ],
    ),
    "secrets": (
        ["- id: gitleaks", "- id: detect-private-key", "- id: detect-secrets", "run: trufflehog git file://."],
        ["- id: check-yaml", "- id: debug-statements"],
    ),
}

# What the root instruction files say (as written): topic, texts that count, near misses
SAY = {
    "tests": (
        [
            "Run `pnpm test` before you commit.",
            "Run `uv run pytest -q`",
            "go test ./...",
            "make test",
            "Run PNPM TEST",
            "pnpm --filter=@x/y test",
        ],
        [
            "Write tests for every change",
            "The latest release",
            "Tests live in `spec/`",
            "Vitest tests are colocated",
            "Jest mocks",
            "toxic",
            "Noxus",
        ],
    ),
    # a full command counts anywhere; a bare tool name does not (see test_instructions_say_function)
    "lint": (
        ["Run `pnpm lint`", "ruff check .", "cargo clippy -- -D warnings", "pnpm lint"],
        ["Keep the code clean", "Use a linter", "run prettier --write", "Use ESLint"],
    ),
    "types": (
        [
            "Run `pnpm typecheck`",
            "tsc --noEmit",
            "go vet ./...",
            "pnpm --filter=@x/y typescript:check",
            "pnpm typecheck",
        ],
        ["Use strict types", "TypeScript only", "see tsconfig.json", "type check with mypy", "mypy (partial)"],
    ),
    "security": (
        ["## Security", "# Security rules", "### Security and secrets"],
        ["Security is important", "Use secure defaults", "## Insecure demo"],
    ),
    "secrets": (
        [
            "Never commit secrets",
            "Do not log tokens or passwords",
            "Never hardcode API keys",
            "Don't commit .env files",
            "Never commit secrets or API keys",
            "Secrets MUST NOT appear in log lines",
            "Never stage or publish credentials",
            "Never commit `.env`",
        ],
        [
            "Commit often",
            "Never use force push",
            "Do not skip the tests",
            "Never log the keyboard",
            "Never hardcode colors; use design tokens",
        ],
    ),
}

# A permission rule that keeps an agent away from secrets (lowercased first)
SECRET = (
    [
        "read(./.env)",
        "read(**/.env*)",
        "read(./secrets/**)",
        "read(**/*.pem)",
        "read(~/.ssh/id_rsa)",
        "read(./credentials.json)",
        "read(**/*.key)",
        "read(~/.aws/credentials)",
        "read(~/.ssh/config)",
        "read(**/*.p12)",
        "read(./.npmrc)",
        "read(./.keys.json)",
    ],
    [
        "bash(rm -rf *)",
        "read(./src/**)",
        "bash(git push:*)",
        "webfetch(domain:example.com)",
        "read(./.environment)",
        "read(./.environment/x)",
        "read(./.envrc)",
    ],
)

# A security policy that speaks of reports found or written with AI (lowercased first)
POLICY_AI = (
    [
        "ai-generated reports will be closed",
        "do not submit reports generated by an llm",
        "please say if you used ai to find the issue",
        "we see a lot of ai slop",
        "llm-generated reports",
        "reports written with ai assistance",
    ],
    [
        "report vulnerabilities privately by email",
        "we support the latest two major versions",
        "please include a proof of concept",
    ],
)

# Code files and test files, by path: code files, test files, neither
CODE = [
    "src/a.ts",
    "a.py",
    "main.go",
    "lib.rs",
    "src/Foo.java",
    "a.kt",
    "a.rb",
    "a.php",
    "A.cs",
    "a.swift",
    "a.c",
    "a.cpp",
    "a.h",
    "a.exs",
    "a.vue",
    "a.svelte",
    "a.dart",
    "a.jsx",
    "a.mts",
    "src/latest/a.ts",
    "src/contest.ts",
]
NOT_CODE = ["README.md", "a.json", "a.yaml", "Makefile", "a.lock", "a.css", "a.png"]
# build/ and out/ are output at the root only: deeper they are folders of source
OTHERS_CODE = [
    "node_modules/x/a.js",
    "a.d.ts",
    "dist/a.js",
    "vendor/lib/a.go",
    "public/jquery.min.js",
    "third_party/x/a.c",
    "out/a.js",
    "build/a.js",
    "build/sub/a.js",
    "packages/x/dist/a.js",
]
OWN_CODE = [
    "src/a.js",
    "src/builder/a.js",
    "src/distribution/a.js",
    "src/outline/a.js",
    "a.ts",
    "src/vendor-utils/a.js",
    "web/build/app.js",
    "packages/next/src/build/index.ts",
    "src/out/a.js",
    "apps/web/out/a.js",
]
TESTS = [
    "tests/a.py",
    "test/foo.js",
    "src/__tests__/a.ts",
    "a.test.ts",
    "a.spec.tsx",
    "a_test.go",
    "test_a.py",
    "src/test_a.py",
    "spec/models/user_spec.rb",
    "e2e/login.ts",
    "cypress/e2e/a.cy.ts",
    "a.e2e.ts",
    "foo_test.rs",
    "foo_test.exs",
    "src/testing/helpers.ts",
    "lib/foo-test.js",
    "src/test/java/a/B.java",
    "a_test.dart",
    "tests.py",
    "pkg/tests.py",
    "conftest.py",
    "pkg/conftest.py",
]
NOT_TESTS = [
    "src/latest/a.ts",
    "src/contest.ts",
    "src/Foo.java",
    "src/protest.py",
    "src/attestation/a.go",
    "src/testimony.ts",
    "src/specification/a.ts",
    "src/a.stories.tsx",
    "src/inspect.go",
    "test_utils/foo.py",
    "a/tests.pyc",
    "src/mytests.py",
    "contest.py",
    "conftest.pyc",
]
JVM_TESTS = [
    "src/FooTest.java",
    "FooTests.cs",
    "FooSpec.scala",
    "FooIT.java",
    "FooTests.swift",
    "FooTest.kt",
    "Test.java",
    "TestFoo.java",
    "src/TestFoo.java",
    "TestFoo.kt",
    "TestFoo.scala",
]
NOT_JVM_TESTS = [
    "src/Foo.java",
    "Latest.java",
    "Contest.java",
    "Edit.java",
    "FooTest.go",
    "FooTest.java.bak",
    "Foo.kt",
    "Testimony.java",
    "src/Testimony.java",
    "Testing.java",
    "Testfoo.java",
    "TestFoo.go",
]


def counted(path):
    return {rule for rule, shipped, _ in fp.match(path) if not shipped}


class Paths(unittest.TestCase):
    def test_every_rule_has_examples(self):
        self.assertEqual(set(PATHS), set(fp.RULES))

    def test_rules_count_their_paths(self):
        for rule, (hits, _) in PATHS.items():
            for path in hits:
                with self.subTest(rule=rule, path=path):
                    self.assertIn(rule, counted(path))

    def test_rules_leave_near_misses_out(self):
        for rule, (_, misses) in PATHS.items():
            for path in misses:
                with self.subTest(rule=rule, path=path):
                    self.assertNotIn(rule, counted(path))

    def test_root_is_told_apart(self):
        at_root = {rule: root for rule, _, root in fp.match(".claude/CLAUDE.md")}
        self.assertTrue(at_root["claude_md"])
        at_root = {rule: root for rule, _, root in fp.match("packages/api/CLAUDE.md")}
        self.assertFalse(at_root["claude_md"])

    def test_shipped_material_is_not_counted(self):
        for path in SHIPPED:
            with self.subTest(path=path):
                found = list(fp.match(path))
                self.assertTrue(found, "a rule should see it")
                self.assertTrue(all(shipped for _, shipped, _ in found), found)
        for path in NOT_SHIPPED:
            with self.subTest(path=path):
                self.assertTrue(counted(path), path)

    def test_is_shipped(self):
        for pre in ("templates/", "a/examples/", "my-template/", "test/", "__tests__/", "evals/", "Fixtures/", "dist/"):
            self.assertTrue(fp.is_shipped(pre), pre)
        for pre in ("", "packages/api/", "latest/", "testing/", "contest/", "exemplary/", "docs/"):
            self.assertFalse(fp.is_shipped(pre), pre)

    def test_is_shipped_lets_test_folders_through(self):
        for pre in ("test/", "tests/", "a/__tests__/", "e2e/", "TESTS/"):
            self.assertFalse(fp.is_shipped(pre, in_tests=True), pre)
        # vendored and shipped material stays out, inside a test folder too. evals and benchmarks are
        # shipped material, not test folders: they left TEST_DIRS
        for pre in (
            "node_modules/",
            "examples/",
            "templates/",
            "tests/fixtures/",
            "test/node_modules/a/",
            "dist/",
            "mocks/",
            "snapshots/",
            "testdata/",
            "e2e/examples/",
            "my-demos/",
            "evals/",
            "eval/",
            "benchmarks/",
            "tests/evals/",
        ):
            self.assertTrue(fp.is_shipped(pre, in_tests=True), pre)
        self.assertEqual(fp.TEST_DIRS, {"test", "tests", "__tests__", "e2e"})

    def test_is_shipped_lens_adds_folders_for_the_checks_and_security_only(self):
        for pre in (
            "bench/",
            "test-applications/",
            "test-apps/",
            "a/__testfixtures__/",
            "sandbox/",
            "Sandbox/",
            "sandboxes/",
            "test-app/",
            "test-application/",
        ):
            self.assertFalse(fp.is_shipped(pre), pre)
            self.assertFalse(fp.is_shipped(pre, in_tests=True), pre)
            self.assertTrue(fp.is_shipped(pre, lens=True), pre)
            self.assertTrue(fp.is_shipped(pre, in_tests=True, lens=True), pre)
        # the folders that were already shipped stay shipped, and a lens never un-ships anything
        for pre in ("templates/", "node_modules/", "tests/", "evals/"):
            self.assertTrue(fp.is_shipped(pre, lens=True), pre)
        self.assertFalse(fp.is_shipped("tests/", in_tests=True, lens=True))
        for pre in ("", "packages/api/", "benchmark/", "benches/", "sandboxing/"):
            self.assertFalse(fp.is_shipped(pre, lens=True), pre)

    def test_lens_rules_are_the_checks_and_security_rules(self):
        self.assertLessEqual(fp.LENS_RULES, set(fp.RULES))
        self.assertLessEqual(fp.WHOLE_PATH, set(fp.RULES))
        for rule in (
            "claude_md",
            "agents_md",
            "skills",
            "commands",
            "subagents",
            "mcp_config",
            "hooks_files",
            "shared_settings",
            "plans",
            "memory",
            "ai_policy",
            "workflows",
            "skill_files",
            "cursor_rules",
        ):
            self.assertNotIn(rule, fp.LENS_RULES, rule)
        for rule in (
            "oxlint",
            "biome",
            "eslint",
            "custom_lint",
            "git_hooks",
            "vitest",
            "checks_ext",
            "security_md",
            "dependabot",
            "zizmor",
            "secret_scan",
            "dep_audit",
            "security_ext",
            "pkg_files",
            "pkg_nested",
            "fuzz_tests",
        ):
            self.assertIn(rule, fp.LENS_RULES, rule)

    def test_lens_folders_are_shipped_for_the_checks_and_security_rules(self):
        for path, rule in (
            ("sandbox/vitest.config.ts", "vitest"),
            ("bench/biome.json", "biome"),
            ("test-applications/a/eslint.config.js", "eslint"),
            ("a/test-apps/b/jest.config.js", "jest"),
            ("__testfixtures__/a/.eslintrc", "eslint"),
            ("bench/.husky/pre-commit", "git_hooks"),
            ("sandbox/.claude/commands/run-tests.md", "checks_ext"),
            ("sandbox/.claude/commands/security-review.md", "security_ext"),
            ("sandboxes/app/.npmrc", "pkg_nested"),
            ("bench/tools/eslint-rules/a.js", "custom_lint"),
        ):
            with self.subTest(path=path):
                shipped = {r: s for r, s, _ in fp.match(path)}
                self.assertIn(rule, shipped, "a rule should see it")
                self.assertTrue(shipped[rule])
                self.assertNotIn(rule, counted(path))

    def test_lens_folders_leave_the_agent_rules_alone(self):
        for path, rule in (
            ("sandbox/.claude/skills/x/SKILL.md", "skills"),
            ("bench/CLAUDE.md", "claude_md"),
            ("test-applications/a/AGENTS.md", "agents_md"),
            ("sandbox/.mcp.json", "mcp_config"),
            ("sandbox/.claude/commands/ship.md", "commands"),
            ("a/sandbox/.claude/settings.json", "shared_settings"),
            ("bench/.claude/hooks/format.sh", "hooks_files"),
            ("sandbox/docs/plans/a.md", "plans"),
            ("__testfixtures__/.cursor/rules/a.mdc", "cursor_rules"),
        ):
            with self.subTest(path=path):
                shipped = {r: s for r, s, _ in fp.match(path)}
                self.assertIn(rule, shipped, "a rule should see it")
                self.assertFalse(shipped[rule], "not shipped for an agent rule")
                self.assertIn(rule, counted(path))
        # same folders, same agent rule, so the same answer with or without the lens argument
        self.assertFalse(fp.is_shipped("sandbox/"))
        self.assertFalse(fp.is_shipped("bench/"))

    def test_plugin_released(self):
        for path, folder in (
            ("eslint-plugin-foo/CHANGELOG.md", "eslint-plugin-foo/"),
            ("tools/eslint-plugins/LICENSE", "tools/eslint-plugins/"),
            ("packages/oxlint-plugin/CHANGELOG", "packages/oxlint-plugin/"),
            ("a/biome-plugins/.npmignore", "a/biome-plugins/"),
            ("oxlint-plugin-x/license.md", "oxlint-plugin-x/"),
            ("eslint-plugin/ChangeLog.md", "eslint-plugin/"),
        ):
            with self.subTest(path=path):
                m = fp.PLUGIN_RELEASED.match(path)
                self.assertTrue(m)
                self.assertEqual(m.group(1), folder)
        for path in (
            "eslint-plugin-foo/README.md",
            "eslint-plugin-foo/package.json",
            "eslint-rules/CHANGELOG.md",
            "eslint-plugin-foo/src/CHANGELOG.md",
            "eslint-plugin-foo/rules/a.js",
            "plugins/CHANGELOG.md",
            "CHANGELOG.md",
            "biome-plugin-foo/x/LICENSE",
        ):
            with self.subTest(miss=path):
                self.assertIsNone(fp.PLUGIN_RELEASED.match(path))

    def test_in_tests_is_made_of_known_names(self):
        self.assertLessEqual(fp.IN_TESTS, set(fp.RULES))
        self.assertLessEqual(fp.TEST_DIRS, fp.SHIPPED)

    def test_rules_of_checks_are_counted_inside_test_folders(self):
        # only the test runners and the fuzz tests get the test-folder pass
        self.assertEqual(
            fp.IN_TESTS, {"vitest", "jest", "playwright", "cypress", "pytest", "mutation_tests", "fuzz_tests"}
        )
        for path, rule in (
            ("e2e/playwright.config.ts", "playwright"),
            ("tests/conftest.py", "pytest"),
            ("test/jest.config.js", "jest"),
            ("packages/a/__tests__/vitest.config.ts", "vitest"),
            ("tests/cypress.config.ts", "cypress"),
            ("e2e/stryker.config.json", "mutation_tests"),
            ("test/vitest.e2e.config.ts", "vitest"),
            ("tests/fuzz/fuzz_parse.py", "fuzz_tests"),
        ):
            with self.subTest(path=path):
                self.assertIn(rule, counted(path))

    def test_lint_configs_and_git_hooks_are_not_counted_inside_test_folders(self):
        for path, rule in (
            ("tests/biome.json", "biome"),
            ("test/.eslintrc.json", "eslint"),
            ("e2e/prettier.config.js", "prettier"),
            ("tests/knip.json", "knip"),
            ("tests/.oxlintrc.json", "oxlint"),
            ("tests/.oxfmtrc.json", "oxfmt"),
            ("test/dependency-cruiser.config.mjs", "import_rules"),
            ("tests/.lintstagedrc", "lint_staged"),
            ("tests/.husky/pre-commit", "git_hooks"),
            ("tests/lefthook.yml", "git_hooks"),
            ("tests/eslint-rules/no-foo.js", "custom_lint"),
            ("evals/biome.json", "biome"),
            ("benchmarks/vitest.config.ts", "vitest"),
            ("eval/jest.config.js", "jest"),
        ):
            with self.subTest(path=path):
                shipped = {r: s for r, s, _ in fp.match(path)}
                self.assertIn(rule, shipped, "a rule should see it")
                self.assertTrue(shipped[rule])
                self.assertNotIn(rule, counted(path))

    def test_custom_lint_tests_every_folder_of_the_path(self):
        self.assertEqual(fp.WHOLE_PATH, {"custom_lint"})
        for path in (
            "eslint-rules/__tests__/x.js",
            "biome-plugins/fixtures/a.grit",
            "eslint-rules/test/a.js",
            "tools/eslint-rules/fixtures/valid/a.js",
            "eslint-rules/examples/a.js",
        ):
            with self.subTest(path=path):
                self.assertEqual([(r, s) for r, s, _ in fp.match(path)], [("custom_lint", True)])
        for path in ("eslint-rules/x.js", "biome-plugins/a.grit", "tools/lint-rules/sub/a.py"):
            with self.subTest(path=path):
                self.assertEqual([(r, s) for r, s, _ in fp.match(path)], [("custom_lint", False)])
        # at_root still reads the part before the fingerprint
        self.assertEqual([r for _, _, r in fp.match("eslint-rules/x.js")], [True])
        self.assertEqual([r for _, _, r in fp.match("tools/eslint-rules/x.js")], [False])

    def test_rules_of_checks_are_not_counted_in_vendored_or_shipped_folders(self):
        for path, rule in (
            ("node_modules/pkg/jest.config.js", "jest"),
            ("examples/app/vitest.config.ts", "vitest"),
            ("templates/next/biome.json", "biome"),
            ("tests/fixtures/conftest.py", "pytest"),
            ("e2e/examples/playwright.config.ts", "playwright"),
            ("fixtures/app/.eslintrc.json", "eslint"),
            ("tests/node_modules/a/knip.json", "knip"),
            ("test/testdata/cypress.config.ts", "cypress"),
        ):
            with self.subTest(path=path):
                shipped = {r: s for r, s, _ in fp.match(path)}
                self.assertIn(rule, shipped, "a rule should see it")
                self.assertTrue(shipped[rule])
                self.assertNotIn(rule, counted(path))

    def test_other_rules_are_still_not_counted_inside_test_folders(self):
        for path, rule in (
            ("test/fixtures/.mcp.json", "mcp_config"),
            ("tests/.claude/settings.json", "shared_settings"),
            ("e2e/.claude/skills/a/SKILL.md", "skills"),
            ("test/CLAUDE.md", "claude_md"),
            ("evals/task/.github/prompts/a.prompt.md", "commands"),
            ("tests/.claude/commands/run-tests.md", "checks_ext"),
            ("tests/.claude/commands/security-review.md", "security_ext"),
        ):
            with self.subTest(path=path):
                shipped = {r: s for r, s, _ in fp.match(path)}
                self.assertIn(rule, shipped, "a rule should see it")
                self.assertTrue(shipped[rule])

    def test_not_this(self):
        self.assertEqual(
            set(fp.NOT_THIS),
            {
                "plans",
                "mcp_config",
                "custom_lint",
                "git_hooks",
                "security_md",
                "compose",
                "coverage_config",
                "changelog_dir",
            },
        )
        # a workflow named for a tool does not count as the tool: the near misses are in PATHS, the hits beside them here
        self.assertNotIn("compose", counted(".github/workflows/docker-compose.yml"))
        self.assertIn("compose", counted(".github/resources/docker-compose.yml"))
        self.assertNotIn("coverage_config", counted("vendored/rusqlite/codecov.yml"))
        self.assertIn("coverage_config", counted("packages/api/.nycrc"))
        self.assertNotIn("changelog_dir", counted("changelog/3.244.0.md"))
        self.assertIn("changelog_dir", counted(".changes/3.244.0.md"))
        # a hook script under an agent directory is an agent hook, not a git hook
        self.assertNotIn("git_hooks", counted(".claude/hooks/pre-commit"))
        self.assertIn("hooks_files", counted(".claude/hooks/pre-commit"))
        self.assertNotIn("git_hooks", counted("web/.codex/hooks/pre-push"))
        self.assertIn("git_hooks", counted("web/hooks/pre-push"))
        # exactly lower-case docs/security.md is a page of the docs
        self.assertNotIn("security_md", counted("docs/security.md"))
        self.assertNotIn("security_md", counted("doc/security.md"))
        self.assertIn("security_md", counted("docs/SECURITY.md"))
        self.assertIn("security_md", counted("docs/Security.md"))
        self.assertIn("security_md", counted("security.md"))
        self.assertNotIn("plans", counted(".agents/skills/plan/references/PLAN.md"))
        self.assertIn("plans", counted("docs/PLAN.md"))
        self.assertNotIn("mcp_config", counted("providers/claude/.mcp.json"))
        self.assertIn("mcp_config", counted("apps/api/.mcp.json"))
        self.assertNotIn("custom_lint", counted("docs/eslint-rules/no-foo.md"))
        self.assertNotIn("custom_lint", counted("website/biome-plugins/no-foo.grit"))
        self.assertIn("custom_lint", counted("tools/eslint-rules/no-foo.js"))

    def test_prefilter_lets_every_example_through(self):
        for rule, (hits, _) in PATHS.items():
            for path in hits:
                self.assertTrue(fp.PREFILTER.search(path), path)


class Links(unittest.TestCase):
    def test_match_link(self):
        self.assertEqual(fp.match_link(".claude/skills"), ("skills", False, True))
        self.assertEqual(fp.match_link("packages/a/.claude/commands"), ("commands", False, False))
        self.assertEqual(fp.match_link(".github/prompts"), ("commands", False, True))
        self.assertEqual(fp.match_link(".claude/agents"), ("subagents", False, True))
        self.assertEqual(fp.match_link(".cursor/rules"), ("cursor_rules", False, True))
        self.assertEqual(fp.match_link(".windsurf/rules"), ("windsurf_rules", False, True))
        self.assertEqual(fp.match_link(".claude/rules"), ("other_rules", False, True))
        self.assertEqual(fp.match_link("examples/x/.claude/skills"), ("skills", True, False))

    def test_match_link_near_misses(self):
        for path in (".claude/skills/review", "claude/skills", ".junie/rules", ".claude/settings", "skills"):
            self.assertIsNone(fp.match_link(path), path)

    def test_still_valid(self):
        self.assertTrue(fp.still_valid("skills", ".claude/skills/a/SKILL.md"))
        self.assertTrue(fp.still_valid("skills", ".claude/skills"))  # a linked directory
        self.assertFalse(fp.still_valid("commands", ".claude/skills"))
        self.assertFalse(fp.still_valid("skills", "templates/.claude/skills/a/SKILL.md"))
        self.assertFalse(fp.still_valid("plans", ".claude/skills/p/references/plan.md"))
        self.assertFalse(fp.still_valid("claude_md", "AGENTS.md"))
        self.assertFalse(fp.still_valid("skills", "examples/.claude/skills"))


class Content(unittest.TestCase):
    def check(self, table, rules):
        self.assertEqual(set(table), set(rules))
        for agent, (hits, misses) in table.items():
            for text in hits:
                with self.subTest(agent=agent, text=text):
                    self.assertTrue(rules[agent].search(text))
            for text in misses:
                with self.subTest(agent=agent, miss=text):
                    self.assertFalse(rules[agent].search(text))

    def test_ci_agents(self):
        self.check(CI, fp.CI_AGENTS)

    def test_commit_identity(self):
        self.check(IDENTITY, fp.COMMIT_IDENTITY)

    def test_people_match_no_agent(self):
        for _, (_, people) in IDENTITY.items():
            for ident in people:
                self.assertEqual([k for k, rx in fp.COMMIT_IDENTITY.items() if rx.search(ident)], [], ident)

    def test_commit_body(self):
        self.check(BODY, fp.COMMIT_BODY)

    def test_model_key_is_not_an_agent_in_ci(self):
        self.assertTrue(fp.CI_LLM_KEY.search("anthropic_api_key: ${{ secrets.k }}"))
        self.assertEqual([k for k, rx in fp.CI_AGENTS.items() if rx.search("anthropic_api_key: x")], [])

    def check_files(self, table, rules):
        """A table of {key: {file: (hits, misses)}} against rules shaped the same way."""
        self.assertEqual(set(table), set(rules))
        for key, files in table.items():
            self.assertEqual(set(files), set(rules[key]), key)
            self.check({(key, f): v for f, v in files.items()}, {(key, f): rules[key][f] for f in files})

    def test_ci_checks(self):
        self.check(CHECKS, fp.CI_CHECKS)

    def test_ci_scanners(self):
        self.check(SCANNERS, fp.CI_SCANNERS)

    def test_ci_supply(self):
        self.check(SUPPLY, fp.CI_SUPPLY)

    def test_ci_supply_inputs(self):
        self.check(SUPPLY_INPUTS, fp.CI_SUPPLY_INPUTS)

    def test_ci_supply_does_not_name_a_scanner_twice(self):
        # what it adds is not a key of CI_SCANNERS, so no list of scanners counts a tool twice
        self.assertEqual(set(fp.CI_SUPPLY) & set(fp.CI_SCANNERS), set())

    def test_workflow_token_and_checkout(self):
        self.assertEqual(fp.TOP_PERMISSIONS.findall("on: push\npermissions:\n  contents: read\njobs: {}\n"), [""])
        self.assertEqual(fp.TOP_PERMISSIONS.findall("permissions: read-all\n"), ["read-all"])
        self.assertEqual(fp.TOP_PERMISSIONS.findall("jobs:\n  a:\n    permissions: write-all\n"), [])
        self.assertTrue(fp.JOBS_KEY.search("on: push\njobs:\n  a:\n"))
        self.assertFalse(fp.JOBS_KEY.search("on: push\n  jobs:\nmy_jobs:\n"))
        for text in (
            "- uses: actions/checkout@v4",
            "    uses: actions/checkout@" + "a" * 40,
            "  - uses: 'actions/checkout@v4'",
        ):
            with self.subTest(text=text):
                self.assertTrue(fp.CHECKOUT.search(text))
        for text in ("- uses: actions/checkout-x@v4", "- uses: acme/checkout@v4", "- run: echo actions/checkout@v4"):
            with self.subTest(miss=text):
                self.assertFalse(fp.CHECKOUT.search(text))
        self.assertTrue(fp.NO_PERSIST.search("  with:\n    persist-credentials: false\n"))
        self.assertTrue(fp.NO_PERSIST.search("    persist-credentials: 'false'"))
        for text in (
            "    persist-credentials: true",
            "    persist-credentials: ${{ inputs.x }}",
            "    # persist-credentials: false x",
        ):
            with self.subTest(miss=text):
                self.assertFalse(fp.NO_PERSIST.search(text))

    def test_scanner_jobs_name_known_scanners(self):
        self.assertEqual(set(fp.SCANNER_JOBS), {"code", "deps", "secrets", "workflows"})
        for job, tools in fp.SCANNER_JOBS.items():
            self.assertLessEqual(set(tools), set(fp.CI_SCANNERS), job)
        self.assertIn("snyk", fp.SCANNER_JOBS["code"])
        self.assertIn("snyk", fp.SCANNER_JOBS["deps"])

    def test_ci_agent_fence(self):
        self.check(FENCE, fp.CI_AGENT_FENCE)

    def test_ops_run(self):
        self.check(OPS_RUN, fp.OPS_RUN)

    def test_ops_text(self):
        self.check(OPS_TEXT, fp.OPS_TEXT)

    def test_os_label(self):
        for text in ("runs-on: windows-latest", "os: [ubuntu-latest, macos-14]", "- windows-2022", "macos-15-xlarge"):
            self.assertTrue(fp.OS_LABEL.search(text), text)
        for text in ("target: x86_64-pc-windows-msvc", "path: dist/windows-2022/", "runs-on: windows", "macos-arm64"):
            self.assertFalse(fp.OS_LABEL.search(text), text)

    def test_step_inputs(self):
        self.assertTrue(fp.SETUP_ACTION.match("actions/setup-node@v4"))
        self.assertTrue(fp.SETUP_ACTION.match("astral-sh/setup-uv@v6"))
        self.assertFalse(fp.SETUP_ACTION.match("docker/setup-buildx-action-x"))
        for text in ("  cache: npm", "  enable-cache: true", "  bundler-cache: true", "  cache: ${{ inputs.c }}"):
            self.assertTrue(fp.SETUP_CACHE.search(text), text)
        for text in (
            "  cache: false",
            "  cache: ''",
            "  cache:",
            "  cache-dependency-path: a.lock",
            "  no-cache: true",
        ):
            self.assertFalse(fp.SETUP_CACHE.search(text), text)
        self.assertTrue(fp.BUILD_PUSH_ACTION.match("depot/build-push-action@v1"))
        self.assertTrue(fp.BUILD_PUSH_ACTION.match("docker/bake-action@v6"))
        for text in ("  push: true", "  push: ${{ github.event_name != 'pull_request' }}", "  outputs: type=registry"):
            self.assertTrue(fp.PUSH_INPUT.search(text), text)
        for text in ("  push: false", "  push: 'false'", "  load: true", "  outputs: type=docker"):
            self.assertFalse(fp.PUSH_INPUT.search(text), text)

    def test_the_readers_of_issue_1_name_no_personal_account(self):
        # an action kept on a person's account is matched by its repo name: every owner written in a rule is an organisation
        owners = set()
        for table in (fp.OPS_RUN, fp.OPS_TEXT):
            for rx in table.values():
                owners |= set(re.findall(r"\^([a-z][\w-]*)/", rx.pattern))
        self.assertLessEqual(
            owners,
            {
                "codecov",
                "coverallsapp",
                "changesets",
                "actions",
                "cloudflare",
                "azure",
                "aws-actions",
                "google-github-actions",
            }
            | {"pypa", "rubygems"},
        )

    def test_fork_trigger_is_read_in_the_on_block_only(self):
        self.assertNotIn("target", fp.CI_AGENT_FENCE)

        def fork(text):
            m = fp.ON_BLOCK.search(text)
            return bool(m and fp.FORK_TRIGGER.search(m.group(1)))

        for text in (
            "on: pull_request_target",
            "on:\n  pull_request_target:\n    types: [opened]",
            "name: x\non:\n  issue_comment:\n  pull_request_target:\njobs:\n  a:\n",
            "'on':\n  pull_request_target:\n",
        ):
            with self.subTest(text=text):
                self.assertTrue(fork(text))
        for text in (
            "on: pull_request",
            "on: workflow_run",
            "on: pull_request\nconcurrency:\n  group: pull_request_target",
            "on:\n  pull_request:\njobs:\n  a:\n    if: github.event_name == 'pull_request_target'\n",
            "on:\n  pull_request_target_x:\n",
        ):
            with self.subTest(miss=text):
                self.assertFalse(fork(text))

    def test_action_use(self):
        sha = "a" * 20 + "0123456789" + "b" * 10
        found = {
            "uses: owner/repo@" + sha: [("owner", sha)],
            "- uses: actions/checkout@v4": [("actions", "v4")],
            "uses: 'github/codeql-action/analyze@v3'": [("github", "v3")],
            "uses: org/repo/.github/workflows/x.yml@main": [("org", "main")],
            "- uses: a/b@v1\n- uses: c/d@v2": [("a", "v1"), ("c", "v2")],
        }
        for text, expected in found.items():
            with self.subTest(text=text):
                self.assertEqual(fp.ACTION_USE.findall(text), expected)
        for text in (
            "uses: ./local-action",
            "uses: docker://alpine",
            "uses: ./.github/actions/setup",
            "run: echo reuses: owner/repo",
            "uses: owner/repo",
        ):
            with self.subTest(miss=text):
                self.assertEqual(fp.ACTION_USE.findall(text), [])
        self.assertEqual(fp.FIRST_PARTY_ACTIONS, ("actions", "github"))

    def test_cooldown(self):
        self.check_files(COOL, fp.COOLDOWN)

    def test_package_guards(self):
        self.check_files(GUARDS, fp.PACKAGE_GUARDS)

    def test_package_tools(self):
        self.assertEqual(set(PACKAGE), set(fp.PACKAGE_TOOLS))
        for tool, (name, misses) in PACKAGE.items():
            with self.subTest(tool=tool):
                self.assertTrue(fp.PACKAGE_TOOLS[tool].search('"devDependencies": {"%s": "^1.0.0"}' % name))
            for text in misses:
                with self.subTest(tool=tool, miss=text):
                    self.assertFalse(fp.PACKAGE_TOOLS[tool].search(text))

    def test_pyproject_tools(self):
        self.check(PYPROJECT, fp.PYPROJECT_TOOLS)

    def test_hook_checks(self):
        self.check(HOOK, fp.HOOK_CHECKS)

    def test_hook_events(self):
        events = {
            "before": (
                fp.HOOK_BEFORE,
                ["pretooluse", "beforeshellexecution", "beforesubmitprompt", "permissionrequest", "userpromptsubmit"],
                ["posttooluse", "sessionstart", "stop", "notification", "afterfileedit", "precompact"],
            ),
            "after": (
                fp.HOOK_AFTER,
                ["posttooluse", "afterfileedit", "stop", "subagentstop", "afteragentresponse"],
                ["pretooluse", "sessionstart", "notification", "beforeshellexecution"],
            ),
            "start": (
                fp.HOOK_START,
                ["sessionstart", "setup", "worktreecreate"],
                ["pretooluse", "stop", "notification", "sessionend"],
            ),
        }
        for name, (rx, hits, misses) in events.items():
            for event in hits:
                with self.subTest(moment=name, event=event):
                    self.assertTrue(rx.search(event))
            for event in misses:
                with self.subTest(moment=name, miss=event):
                    self.assertFalse(rx.search(event))

    def test_git_hook_jobs(self):
        """The patterns are meant for text cleaned with HOOK_NOISE: comments and commitlint removed."""
        self.assertEqual(set(GIT_HOOK), set(fp.GIT_HOOK_JOBS))
        for job, (hits, misses) in GIT_HOOK.items():
            for text in hits:
                with self.subTest(job=job, text=text):
                    self.assertTrue(fp.GIT_HOOK_JOBS[job].search(fp.HOOK_NOISE.sub("", text)))
            for text in misses:
                with self.subTest(job=job, miss=text):
                    self.assertFalse(fp.GIT_HOOK_JOBS[job].search(fp.HOOK_NOISE.sub("", text)))
        # multi-line texts: re.M anchors a script line, a comment is dropped
        text = "#!/bin/sh\n# run pytest here\npnpm exec vitest related\n"
        cleaned = fp.HOOK_NOISE.sub("", text)
        self.assertTrue(fp.GIT_HOOK_JOBS["tests"].search(cleaned))
        self.assertFalse(fp.GIT_HOOK_JOBS["tests"].search(fp.HOOK_NOISE.sub("", "#!/bin/sh\n# run pytest here\n")))
        self.assertFalse(fp.GIT_HOOK_JOBS["lint"].search(fp.HOOK_NOISE.sub("", "npx --no -- commitlint --edit $1\n")))
        for rx in fp.GIT_HOOK_JOBS.values():
            self.assertTrue(rx.flags & re.M)

    def test_instructions_say(self):
        self.check(SAY, fp.INSTRUCTIONS_SAY)

    def test_instructions_say_function(self):
        """instructions_say gives the sorted keys: a full command anywhere, a bare tool name in code formatting only."""
        say = fp.instructions_say
        self.assertEqual(say("Run pnpm test then pnpm lint."), ["lint", "tests"])
        self.assertEqual(say("make test"), ["tests"])
        self.assertEqual(say("pnpm --filter=@x/y typescript:check"), ["types"])
        self.assertEqual(say("## Security\n\nNever commit secrets."), ["secrets", "security"])
        self.assertEqual(say(""), [])
        for text, expected in (
            ("Use `pytest` for tests.", ["tests"]),
            ("Use `jest`.", ["tests"]),
            ("Use `vitest`.", ["tests"]),
            ("```sh\nvitest\n```", ["tests"]),
            ("Format with `prettier`.", ["lint"]),
            ("Lint with `eslint`.", ["lint"]),
            ("Check types: `tsc`.", ["types"]),
            ("`mypy` must pass.", ["types"]),
            ("Run `typecheck`.", ["types"]),
            ("Run `tox`.", ["tests"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(say(text), expected)
        # the bare name in a sentence, a config file name, a plugin: nothing
        for text in (
            "Use pytest for tests.",
            "run prettier --write",
            "type check with mypy",
            "Use ESLint",
            "Vitest tests are colocated",
            "Jest mocks",
            "mypy (partial)",
            "toxic",
            "Noxus",
            "Run tox.",
            "See `jest.config.js`.",
            "See `eslint.config.js`.",
            "Install `pytest-asyncio`.",
            "Edit `tsconfig.json`.",
            "Never log the keyboard",
            "Never hardcode colors; use design tokens",
        ):
            with self.subTest(miss=text):
                self.assertEqual(say(text), [])
        for text in (
            "Never commit secrets or API keys",
            "Secrets MUST NOT appear in log lines",
            "Never stage or publish credentials",
        ):
            with self.subTest(text=text):
                self.assertEqual(say(text), ["secrets"])

    def test_a_type_check_script_is_not_a_test_script(self):
        for text in ("pnpm test:types", "pnpm run test:types", "bun run check:test:types"):
            with self.subTest(text=text):
                self.assertFalse(fp.CI_CHECKS["tests"].search(text))
                self.assertFalse(fp.INSTRUCTIONS_SAY["tests"].search(text))
        self.assertTrue(fp.CI_CHECKS["types"].search("pnpm test:types"))
        self.assertTrue(fp.INSTRUCTIONS_SAY["types"].search("pnpm test:types"))
        self.assertEqual(fp.instructions_say("pnpm test:types"), ["types"])

    def test_instructions_say_commands_in_code(self):
        """Code spans lose their backticks, one span or one line of a block per line; CODE_TEST_LINE reads them."""
        say = fp.instructions_say
        for text, expected in (
            ("`hogli test <file>`", ["tests"]),
            ("```\nbunx turbo run lint test\n```", ["lint", "tests"]),
            ("`./bin/test-agent :only '[x]'`", ["tests"]),
            ("`./scripts/run-tests.sh`", ["tests"]),
            ("`./gradlew test`", ["tests"]),
            ("`docker compose run test`", ["tests"]),
            ("`bun bd test <file>`", ["tests"]),
            ("`pnpm --filter @x/y test`", ["tests"]),
            ("`yarn workspace x test`", ["tests"]),
            ("`npm --prefix web run test:ci`", ["tests"]),
            ("`hogli lint`", ["lint"]),
            ("`pnpm check:lint`", ["lint"]),
            ("`pnpm run check-format`", ["lint"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(say(text), expected)
        for text in (
            "`test_utils.py`",
            "`tests/`",
            "`cd test`",
            "```ts\nit('should test foo', () => {})\n```",
            "```\nsrc/\n  test/\n```",
            "`NODE_ENV=test pnpm dev`",
            "`python test.py`",
            "`name: test`",
            "```yaml\n- name: test\n```",
            "`foo.test.ts`",
            "`et check-packages <package>`",
            "`lint-staged`",
            "We lint the code.",
            "`pnpm run reformat`",
            "`yarn workspace x build`",
            "`pnpm testing`",
        ):
            with self.subTest(miss=text):
                self.assertEqual(say(text), [])
        self.assertTrue(fp.CODE_TEST_LINE.search("hogli test path"))
        self.assertFalse(fp.CODE_TEST_LINE.search("cd test"))

    def test_security_heading_needs_a_heading(self):
        self.assertTrue(fp.INSTRUCTIONS_SAY["security"].search("# Project\n\n## Security\n\ntext"))
        self.assertFalse(fp.INSTRUCTIONS_SAY["security"].search("# Project\n\nSee the security docs.\n"))

    def test_secret_rule(self):
        self.check({"secret": SECRET}, {"secret": fp.SECRET_RULE})

    def test_package_manager(self):
        for text, expected in (
            ('"packagemanager": "pnpm@11.2.0"', ("pnpm", "11", "2")),
            ('"packagemanager":"bun@1.2.3"', ("bun", "1", "2")),
            ('"packagemanager": "yarn@4.15.1+sha512.abc"', ("yarn", "4", "15")),
            ('"packagemanager": "npm@10.8.2"', ("npm", "10", "8")),
        ):
            with self.subTest(text=text):
                self.assertEqual(fp.PACKAGE_MANAGER.search(text).groups(), expected)
        for text in (
            '"packagemanager": "pnpm"',
            '"packagemanager": "npm@10"',
            '"packagemanager": "deno@2.0.0"',
            '"engines": {"pnpm": "11.2.0"}',
        ):
            with self.subTest(miss=text):
                self.assertIsNone(fp.PACKAGE_MANAGER.search(text))
        # texts are lowercased before matching, so the camel-case key is not matched as written
        self.assertIsNone(fp.PACKAGE_MANAGER.search('"packageManager": "pnpm@11.2.0"'))

    def test_script_call(self):
        for text, name in (
            ("pnpm test", "test"),
            ("pnpm run build", "build"),
            ("npm run test:unit", "test:unit"),
            ("yarn -w lint", "lint"),
            ("bun run --if-present e2e", "e2e"),
            ("pnpm -r test", "test"),
        ):
            with self.subTest(text=text):
                self.assertEqual(fp.SCRIPT_CALL.search(text).group(1), name)
        self.assertIsNone(fp.SCRIPT_CALL.search("echo npm"))

    def test_security_policy_ai(self):
        self.check({"policy": POLICY_AI}, {"policy": fp.SECURITY_POLICY_AI})

    def test_code_files(self):
        for path in CODE:
            with self.subTest(path=path):
                self.assertTrue(fp.CODE_FILE.search(path))
                self.assertFalse(fp.NOT_OWN_CODE.search(path))
        for path in NOT_CODE:
            with self.subTest(miss=path):
                self.assertFalse(fp.CODE_FILE.search(path))

    def test_code_that_is_not_the_repos_own(self):
        for path in OTHERS_CODE:
            with self.subTest(path=path):
                self.assertTrue(fp.NOT_OWN_CODE.search(path))
        for path in OWN_CODE:
            with self.subTest(miss=path):
                self.assertFalse(fp.NOT_OWN_CODE.search(path))

    def test_test_files(self):
        for path in TESTS:
            with self.subTest(path=path):
                self.assertTrue(fp.TEST_FILE.search(path))
        for path in NOT_TESTS:
            with self.subTest(miss=path):
                self.assertFalse(fp.TEST_FILE.search(path))

    def test_jvm_test_files(self):
        for path in JVM_TESTS:
            with self.subTest(path=path):
                self.assertTrue(fp.JVM_TEST_FILE.search(path))
        for path in NOT_JVM_TESTS:
            with self.subTest(miss=path):
                self.assertFalse(fp.JVM_TEST_FILE.search(path))


class Identities(unittest.TestCase):
    """What a scan may write out about a commit identity (discovery_identity)."""

    def test_agent_mailboxes_are_kept(self):
        self.assertEqual(
            fp.discovery_identity("claude opus 4.6 <noreply@anthropic.com>"), "claude opus 4.6 <noreply@anthropic.com>"
        )
        self.assertEqual(
            fp.discovery_identity("cursor agent <cursoragent@cursor.com>"), "cursor agent <cursoragent@cursor.com>"
        )

    def test_a_person_name_on_an_agent_mailbox_is_blanked(self):
        self.assertEqual(fp.discovery_identity("jane doe <noreply@anthropic.com>"), "<noreply@anthropic.com>")

    def test_people_are_never_kept(self):
        for ident in (
            "jane doe <jane-example@anthropic.com>",
            "sam example <sam-example@cursor.com>",
            "jane doe <12345+jane-example@users.noreply.github.com>",
            "noreply <noreply@example.com> extra",
            "bot builder <bob@example.com>",
        ):
            self.assertIsNone(fp.discovery_identity(ident), ident)

    def test_a_kept_identity_is_kept_as_is(self):
        for ident in ("claude <noreply@anthropic.com>", "jane doe <noreply@example.com>", "<amp@ampcode.com>"):
            kept = fp.discovery_identity(ident)
            self.assertEqual(fp.discovery_identity(kept), kept)


class Hostile(unittest.TestCase):
    """Every compiled content rule, on texts built to make a regex backtrack: none may take a second.

    Two patterns once hung a scan on a real workflow (a make target made of many words, the block-list branch of the
    `bash` fence). A search is timed one by one, so a slow rule is named in the failure.
    """

    LIMIT = 1.0
    TEXTS = {
        "make, words split by _": "make " + "a_" * 4000 + "x",
        "make, words split by -": "make " + "ab-" * 4000,
        "tools block list": "allowed_tools: |\n" + "  read(x)\n" * 3000 + "prompt: x\n",
        "tools lines": ("allowed_tools: " + "x " * 500 + "\n") * 200,
        "secrets words": "never commit log print " * 3000,
        "pnpm script with colons": "pnpm " + "a:" * 5000 + "x",
        "pnpm run script with dots": "pnpm run " + "a.b-" * 5000,
        "turbo tasks": "turbo run " + "ab " * 5000,
        "pnpm filters": "pnpm " + "--filter x " * 3000 + "build",
        "long words, many lines": ("a " * 2000 + "\n") * 20,
        "a path": "./" + "a/" * 5000 + "x",
        "unclosed json": '{"a":' * 20000,
        # the workflow readers: a tool named again and again on one line, a long action name, keys and spaces
        "nx and turbo words": ("nx turbo kubectl helm gradlew mvn vercel docker build goreleaser " * 30 + "\n") * 50,
        "a long action name": "a-b/" + "x-" * 5000 + "github-app-token",
        "filters and platforms": "--filter=" + "a" * 8000 + " --platform=" + "b" * 8000,
        "keys with trailing spaces": ("cancel-in-progress:" + " " * 3000 + "x\n") * 5,
    }

    @staticmethod
    def rules():
        tables = (
            ("CI_CHECKS", fp.CI_CHECKS),
            ("CI_SCANNERS", fp.CI_SCANNERS),
            ("CI_AGENT_FENCE", fp.CI_AGENT_FENCE),
            ("CI_SUPPLY", fp.CI_SUPPLY),
            ("CI_SUPPLY_INPUTS", fp.CI_SUPPLY_INPUTS),
            ("INSTRUCTIONS_SAY", fp.INSTRUCTIONS_SAY),
            ("INSTRUCTIONS_CODE", fp.INSTRUCTIONS_CODE),
            ("GIT_HOOK_JOBS", fp.GIT_HOOK_JOBS),
            ("HOOK_CHECKS", fp.HOOK_CHECKS),
            ("OPS_RUN", fp.OPS_RUN),
            ("OPS_TEXT", fp.OPS_TEXT),
            ("PLATFORMS_ARM", fp.PLATFORMS_ARM),
        )
        for name, table in tables:
            for key, rx in table.items():
                yield "%s[%s]" % (name, key), rx
        yield "CODE_TEST_LINE", fp.CODE_TEST_LINE
        for name in (
            "TOP_PERMISSIONS",
            "JOBS_KEY",
            "CHECKOUT",
            "NO_PERSIST",
            "ON_BLOCK",
            "OS_LABEL",
            "SETUP_ACTION",
            "SETUP_CACHE",
            "BUILD_PUSH_ACTION",
            "PUSH_INPUT",
            "ECHOED",
        ):
            yield name, getattr(fp, name)
        for i, (action, inputs) in enumerate(fp.DEPLOY_STEP.items()):
            yield "DEPLOY_STEP[%d]" % i, action
            yield "DEPLOY_STEP[%d] input" % i, inputs
        for manager, files in fp.COOLDOWN.items():
            for file, rx in files.items():
                yield "COOLDOWN[%s][%s]" % (manager, file), rx

    def test_the_rules_are_all_there(self):
        self.assertGreaterEqual(len(list(self.rules())), 50)

    def test_the_readers_of_issue_1_take_one_long_line_in_their_stride(self):
        # their gaps within a line are bounded: a line of 100 KB that names the tools again and again stays linear
        line = "nx turbo kubectl helm gradlew mvn vercel docker build goreleaser npm publish ko build " * 1200
        for table in (fp.OPS_RUN, fp.OPS_TEXT):
            for key, rx in table.items():
                with self.subTest(rule=key):
                    start = time.perf_counter()
                    rx.search(line)
                    self.assertLess(time.perf_counter() - start, self.LIMIT, key)

    def test_no_search_takes_a_second(self):
        for name, rx in self.rules():
            for label, text in self.TEXTS.items():
                with self.subTest(rule=name, text=label):
                    start = time.perf_counter()
                    rx.search(text)
                    took = time.perf_counter() - start
                    self.assertLess(took, self.LIMIT, "%s took %.2fs on %s" % (name, took, label))

    def test_the_whole_reading_of_a_hostile_instruction_file_is_fast(self):
        for label, text in self.TEXTS.items():
            with self.subTest(text=label):
                start = time.perf_counter()
                fp.instructions_say(text)
                fp.instructions_say("`" + text.replace("`", "") + "`")
                self.assertLess(time.perf_counter() - start, 2 * self.LIMIT, label)


if __name__ == "__main__":
    unittest.main()
