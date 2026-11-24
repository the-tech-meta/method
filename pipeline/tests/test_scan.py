"""scan.py: its pure functions on small literal inputs, then scan() end to end on throwaway git repos.

No network: a remote is a local repo served over file://. The tests need only the pipeline modules. scan.reread is not
tested here.
"""

import ast
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

import base  # noqa: F401  (puts pipeline/ on the path)
import fingerprints as fp
import scan
import test_fingerprints

SHA = "0123456789abcdef" * 2 + "01234567"  # 40 hex characters


def empty_hooks():
    return {"checks": set(), "guard": 0, "setup": 0, "other": 0}


class Hooks(unittest.TestCase):
    def read(self, cfg):
        out = empty_hooks()
        scan.read_hooks(cfg, out)
        return out

    def test_commands_are_found_at_any_depth(self):
        node = {
            "a": [{"command": "one", "x": {"bash": "two"}}],
            "b": {"prompt": "three", "powershell": "four"},
            "c": {"command": 5},
            "d": "command",
        }
        self.assertEqual(sorted(scan.hook_commands(node)), ["four", "one", "three", "two"])
        self.assertEqual(list(scan.hook_commands("text")), [])

    def test_claude_code_settings(self):
        out = self.read(
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Edit",
                            "hooks": [
                                {"type": "command", "command": "pnpm lint --fix"},
                                {"type": "command", "command": "pnpm exec tsc --noEmit"},
                            ],
                        }
                    ],
                    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./guard.sh"}]}],
                    "SessionStart": [{"hooks": [{"type": "command", "command": "pnpm install"}]}],
                }
            }
        )
        self.assertEqual(out, {"checks": {"lint", "types"}, "guard": 1, "setup": 1, "other": 0})

    def test_a_stop_hook_that_checks(self):
        out = self.read({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "pnpm test"}]}]}})
        self.assertEqual(out, {"checks": {"tests"}, "guard": 0, "setup": 0, "other": 0})

    def test_a_hook_that_checks_nothing_is_other(self):
        out = self.read(
            {
                "hooks": {
                    "Stop": [{"hooks": [{"type": "command", "command": "afplay /System/Library/Sounds/Glass.aiff"}]}]
                }
            }
        )
        self.assertEqual(out, {"checks": set(), "guard": 0, "setup": 0, "other": 1})

    def test_an_event_that_is_none_of_the_moments_is_other(self):
        out = self.read({"hooks": {"Notification": [{"hooks": [{"type": "command", "command": "notify.sh"}]}]}})
        self.assertEqual(out["other"], 1)

    def test_a_guard_counts_each_command(self):
        out = self.read({"hooks": {"UserPromptSubmit": [{"hooks": [{"command": "a.sh"}, {"command": "b.sh"}]}]}})
        self.assertEqual(out["guard"], 2)

    def test_cursor_hooks_json(self):
        out = self.read(
            {
                "version": 1,
                "hooks": {
                    "afterFileEdit": [{"command": "./format.sh"}],
                    "beforeShellExecution": [{"command": "./guard.sh"}],
                },
            }
        )
        self.assertEqual(out, {"checks": {"format"}, "guard": 1, "setup": 0, "other": 0})

    def test_a_config_with_no_hooks_changes_nothing(self):
        for cfg in ({}, {"permissions": {"allow": []}}, {"hooks": {}}, {"hooks": []}, {"hooks": "x"}, None, [], "x"):
            with self.subTest(cfg=cfg):
                self.assertEqual(self.read(cfg), empty_hooks())

    def test_a_check_is_kept_across_files(self):
        out = empty_hooks()
        scan.read_hooks({"hooks": {"PostToolUse": [{"command": "prettier --write"}]}}, out)
        scan.read_hooks({"hooks": {"PostToolUse": [{"command": "pytest -q"}]}}, out)
        self.assertEqual(out["checks"], {"format", "tests"})


class Permissions(unittest.TestCase):
    def test_counts(self):
        got = scan.read_permissions(
            {
                "permissions": {
                    "allow": ["Bash(pnpm test:*)", "Read(./src/**)"],
                    "deny": ["Read(./.env)"],
                    "ask": ["Bash(git push:*)"],
                }
            }
        )
        self.assertEqual(
            got,
            {"allow": 2, "deny": 1, "ask": 1, "secrets": True, "sandbox": False, "no_bypass": False, "mcp_all": False},
        )

    def test_nothing_set(self):
        for cfg in ({}, {"permissions": []}, {"permissions": "x"}, {"permissions": {"allow": None}}):
            with self.subTest(cfg=cfg):
                self.assertEqual(
                    scan.read_permissions(cfg),
                    {
                        "allow": 0,
                        "deny": 0,
                        "ask": 0,
                        "secrets": False,
                        "sandbox": False,
                        "no_bypass": False,
                        "mcp_all": False,
                    },
                )

    def test_secrets_need_a_deny_on_something_secret(self):
        for rule in (
            "Read(./.env)",
            "Read(./secrets/**)",
            "Read(**/*.pem)",
            "Read(~/.ssh/id_rsa)",
            "Read(./credentials.json)",
        ):
            with self.subTest(deny=rule):
                self.assertTrue(scan.read_permissions({"permissions": {"deny": [rule]}})["secrets"])
        self.assertFalse(scan.read_permissions({"permissions": {"deny": ["Bash(rm -rf *)"]}})["secrets"])
        self.assertTrue(scan.read_permissions({"permissions": {"deny": ["Bash(rm -rf *)", "Read(./.env)"]}})["secrets"])

    def test_an_allow_or_ask_on_secrets_is_not_a_guard(self):
        got = scan.read_permissions({"permissions": {"allow": ["Read(./.env)"], "ask": ["Read(./.env)"]}})
        self.assertFalse(got["secrets"])

    def test_sandbox(self):
        self.assertTrue(scan.read_permissions({"sandbox": {"enabled": True}})["sandbox"])
        self.assertFalse(scan.read_permissions({"sandbox": {"enabled": False}})["sandbox"])
        self.assertFalse(scan.read_permissions({"permissions": {}})["sandbox"])
        self.assertFalse(scan.read_permissions({"sandbox": True})["sandbox"])
        # true only with "enabled": true, a sandbox block that sets something else is not a sandbox
        for sandbox in (
            {},
            {"network": {"allowedDomains": []}},
            {"enabled": "true"},
            {"enabled": 1},
            {"enabled": None},
            [],
            "enabled",
        ):
            with self.subTest(sandbox=sandbox):
                self.assertFalse(scan.read_permissions({"sandbox": sandbox})["sandbox"])

    def test_no_bypass(self):
        self.assertTrue(
            scan.read_permissions({"permissions": {"disableBypassPermissionsMode": "disable"}})["no_bypass"]
        )
        self.assertTrue(scan.read_permissions({"disableBypassPermissionsMode": "disable"})["no_bypass"])
        self.assertFalse(scan.read_permissions({"permissions": {"defaultMode": "plan"}})["no_bypass"])
        self.assertFalse(scan.read_permissions({"permissions": {"disableBypassPermissionsMode": "other"}})["no_bypass"])

    def test_mcp_all(self):
        self.assertTrue(scan.read_permissions({"enableAllProjectMcpServers": True})["mcp_all"])
        self.assertFalse(scan.read_permissions({"enableAllProjectMcpServers": False})["mcp_all"])
        self.assertFalse(scan.read_permissions({"enabledMcpjsonServers": ["a"]})["mcp_all"])


CI = (
    """name: ci
on: pull_request
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
      - uses: owner/repo@%s
      - uses: github/codeql-action/analyze@v3
      - run: pnpm test
      - run: pnpm exec tsc --noemit
      # - uses: thirdparty/old@v1
      - uses: ./local-action
      - uses: docker://alpine
"""
    % SHA
)

AGENT = """on: issue_comment
jobs:
  a:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedtools bash
          allowed_bots: dependabot
"""
# the same, with a list of tools that holds no bare bash
AGENT_SCOPED = AGENT.replace("--allowedtools bash", "--allowedtools bash(git:*),read")

NO_AGENT_TARGET = """on: pull_request_target
jobs:
  a:
    steps:
      - run: pnpm lint
"""


class Workflows(unittest.TestCase):
    def test_no_workflow(self):
        self.assertEqual(scan.read_workflows([]), {"ci": [], "scanners": [], "pins": [0, 0, 0, 0], "agent": None})

    def test_checks_scanners_and_pins(self):
        got = scan.read_workflows([CI])
        self.assertEqual(got["ci"], ["tests", "types"])
        self.assertEqual(got["scanners"], ["codeql"])
        # checkout (first party, tag), a SHA from owner/repo, codeql-action (first party, tag)
        self.assertEqual(got["pins"], [1, 2, 1, 0])
        self.assertIsNone(got["agent"])

    def test_pins_are_summed_over_workflows(self):
        got = scan.read_workflows([CI, "steps:\n  - uses: acme/tool@main\n  - uses: acme/other@" + SHA])
        self.assertEqual(got["pins"], [2, 3, 2, 1])

    def test_a_commit_pin_is_a_full_sha(self):
        for ref, pinned in ((SHA, True), (SHA[:7], False), ("v1", False), ("main", False), (SHA.upper(), False)):
            with self.subTest(ref=ref):
                got = scan.read_workflows(["uses: acme/tool@" + ref])["pins"]
                self.assertEqual(got, [1, 0, 1, 0] if pinned else [0, 1, 0, 1])

    def test_first_party_actions(self):
        self.assertEqual(
            scan.read_workflows(["uses: actions/checkout@v4\nuses: github/codeql-action/init@v3"])["pins"], [0, 2, 0, 0]
        )
        # a look-alike owner is third party
        self.assertEqual(scan.read_workflows(["uses: actions-rs/toolchain@v1"])["pins"], [0, 1, 0, 1])

    def test_commented_lines_are_ignored(self):
        got = scan.read_workflows(
            ["# uses: acme/tool@v1\n  # run: pnpm test\n  # uses: anthropics/claude-code-action@v1\n"]
        )
        self.assertEqual(got, {"ci": [], "scanners": [], "pins": [0, 0, 0, 0], "agent": None})

    def test_an_agent_workflow(self):
        got = scan.read_workflows([AGENT])
        self.assertEqual(got["agent"], {"n": 1, "fence": ["bash", "bots", "tools"]})

    def test_a_bash_pattern_is_not_the_whole_shell(self):
        got = scan.read_workflows([AGENT_SCOPED])
        self.assertEqual(got["agent"], {"n": 1, "fence": ["bots", "tools"]})

    def test_the_fence_is_read_from_agent_workflows_only(self):
        got = scan.read_workflows([AGENT, NO_AGENT_TARGET])
        self.assertEqual(got["agent"], {"n": 1, "fence": ["bash", "bots", "tools"]})
        self.assertEqual(got["ci"], ["lint"])  # the other workflow still counts for the checks

    def test_a_fence_flag_of_a_second_agent_workflow_is_kept(self):
        got = scan.read_workflows([AGENT, NO_AGENT_TARGET, "on: pull_request_target\nrun: codex exec 'triage'"])
        self.assertEqual(got["agent"], {"n": 2, "fence": ["bash", "bots", "target", "tools"]})

    def test_target_is_read_in_the_on_block_only(self):
        agent = "      - uses: anthropics/claude-code-action@v1\n"
        for on in (
            "on: pull_request_target\n",
            "on:\n  issue_comment:\n  pull_request_target:\n",
            "on: [pull_request_target]\n",
        ):
            with self.subTest(on=on):
                self.assertIn(
                    "target", scan.read_workflows([on + "jobs:\n  a:\n    steps:\n" + agent])["agent"]["fence"]
                )
        for text in (
            "on: pull_request\nconcurrency:\n  group: pull_request_target\njobs:\n  a:\n    steps:\n" + agent,
            "on: pull_request\njobs:\n  a:\n    if: github.event_name == 'pull_request_target'\n    steps:\n" + agent,
        ):
            with self.subTest(text=text):
                self.assertNotIn("target", scan.read_workflows([text])["agent"]["fence"])
        # a fork trigger in a workflow that calls no agent is no fence flag at all
        self.assertIsNone(scan.read_workflows([NO_AGENT_TARGET])["agent"])

    def test_a_list_of_tools_as_a_block_or_with_bash_as_an_item(self):
        head = "on: issue_comment\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n"
        for tools, bash in (
            ("          allowed_tools: |\n            read\n            bash\n", True),
            ("          allowed_tools:\n            - bash\n            - read\n", True),
            ("          allowed_tools: bash(*)\n", True),
            ("          allowed_tools: |\n            read\n            bash(git:*)\n", False),
            ("          disallowed_tools: bash\n", False),
        ):
            with self.subTest(tools=tools):
                self.assertEqual("bash" in scan.read_workflows([head + tools])["agent"]["fence"], bash)

    def test_bots_need_a_name_and_a_star_is_open(self):
        head = "on: issue_comment\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n"
        fence = lambda line: scan.read_workflows([head + "          " + line + "\n"])["agent"]["fence"]
        self.assertEqual(fence("allowed_bots: dependabot"), ["bots"])
        self.assertEqual(fence('allowed_bots: "*"'), ["open"])
        self.assertEqual(fence('allowed_non_write_users: "*"'), ["open"])
        self.assertEqual(fence("allowed_bots: ''"), [])

    def test_comments_are_stripped_after_a_value_too(self):
        got = scan.read_workflows(
            [
                "steps:\n  - uses: a/b@" + SHA + " # v4\n  - uses: c/d@v1 # zizmor: ignore[x]\n"
                "  - run: echo hi # pnpm test\n  - run: pnpm lint # pnpm test\n"
            ]
        )
        self.assertEqual(got["pins"], [1, 1, 1, 1])
        self.assertEqual(got["ci"], ["lint"])
        self.assertEqual(got["scanners"], [])

    def test_an_action_of_the_repos_own_account_is_not_third_party(self):
        text = (
            "steps:\n  - uses: acme/tool@v1\n  - uses: acme/other@"
            + SHA
            + "\n  - uses: other/x@v2\n  - uses: actions/checkout@v4\n"
        )
        self.assertEqual(scan.read_workflows([text])["pins"], [1, 3, 1, 2])
        self.assertEqual(scan.read_workflows([text], owner="acme")["pins"], [1, 3, 0, 1])
        self.assertEqual(scan.read_workflows([text], "someone-else")["pins"], [1, 3, 1, 2])
        # the owner is lowercased by the caller, as the workflow text is
        self.assertEqual(scan.read_workflows([text], owner="Acme")["pins"], [1, 3, 1, 2])

    def test_checks_are_matched_on_what_is_run(self):
        # step names, path filters, matrix values and an agent's prompt name tools without running them
        text = """on:
  push:
    paths:
      - "src/**/tests/**"
      - "pytest.ini"
jobs:
  a:
    strategy:
      matrix:
        tool: [pytest, eslint, mypy]
    steps:
      - name: run vitest, eslint and tsc
        run: pnpm build
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: run pytest, then eslint and mypy
"""
        got = scan.read_workflows([text])
        self.assertEqual((got["ci"], got["scanners"]), ([], []))
        for run, check in (
            ("pnpm test", "tests"),
            ("make test-unit", "tests"),
            ("pnpm lint", "lint"),
            ("uses: astral-sh/ruff-action@v3", "lint"),
            ("pnpm typecheck", "types"),
        ):
            line = run if run.startswith("uses") else "run: " + run
            with self.subTest(run=run):
                self.assertEqual(scan.read_workflows(["steps:\n  - " + line + "\n"])["ci"], [check])

    def test_a_script_of_the_root_package_json_is_read_as_run(self):
        text = "steps:\n  - run: pnpm ci\n"
        self.assertEqual(scan.read_workflows([text])["ci"], [])
        got = scan.read_workflows(
            [text], scripts={"ci": "pnpm test && pnpm lint", "test": "vitest run", "lint": "eslint ."}
        )
        self.assertEqual(got["ci"], ["lint", "tests"])

    def test_scanners_are_matched_on_the_commands(self):
        text = "steps:\n  - uses: github/codeql-action/upload-sarif@v3\n  - run: uvx zizmor .\n  - name: gitleaks\n    run: echo hi\n"
        self.assertEqual(scan.read_workflows([text])["scanners"], ["zizmor"])


class WorkflowCommands(unittest.TestCase):
    def test_what_a_workflow_runs(self):
        text = (
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - name: pytest\n        run: pnpm build\n"
            "      - run: |\n          pnpm lint\n          echo hello\n\n          make test\n"
            "      - run: >\n          cargo clippy\n      - run:\n          semgrep scan\n"
            "      - uses: nrwl/nx-set-shas@v4\n        with:\n          afterbuild: pnpm typecheck\n"
            "      - name: x\n        script: bandit -r .\n      - run: make lint\n"
        )
        got = scan.workflow_commands(text).split("\n")
        for expected in (
            "actions/checkout@v4",
            "pnpm build",
            "pnpm lint",
            "echo hello",
            "make test",
            "cargo clippy",
            "semgrep scan",
            "nrwl/nx-set-shas@v4",
            "pnpm typecheck",
            "bandit -r .",
            "make lint",
        ):
            self.assertIn(expected, got)

    def test_what_a_workflow_only_names(self):
        text = (
            "name: run the tests\non:\n  push:\n    paths:\n      - 'tests/**'\n      - pytest.ini\n"
            "jobs:\n  a:\n    strategy:\n      matrix:\n        tool: [pytest, eslint]\n    steps:\n"
            "      - name: Run vitest and eslint\n        uses: actions/checkout@v4\n"
            "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: please run pytest\n"
            "          cache: pnpm\n"
        )
        self.assertEqual(scan.workflow_commands(text), "actions/checkout@v4\nanthropics/claude-code-action@v1")

    def test_a_block_ends_at_the_next_key(self):
        # the keys that follow `run:` in the same step (here its name) are not part of the script
        text = "steps:\n  - run: |\n      one\n      two\n    name: run pytest\n  - run: three\n"
        self.assertEqual(scan.workflow_commands(text), "one\ntwo\nthree")
        self.assertEqual(scan.read_workflows([text])["ci"], [])

    def test_nothing(self):
        self.assertEqual(scan.workflow_commands(""), "")
        self.assertEqual(scan.workflow_commands("name: x\non: push\n"), "")


class WithScripts(unittest.TestCase):
    SCRIPTS = {
        "ci": "pnpm test && pnpm lint",
        "test": "vitest run",
        "lint": "eslint .",
        "a": "pnpm b",
        "b": "pnpm c",
        "c": "tsc",
    }

    def test_the_scripts_a_command_calls_are_appended(self):
        got = scan.with_scripts("pnpm ci", self.SCRIPTS)
        self.assertEqual(got.split("\n")[0], "pnpm ci")
        for body in ("pnpm test && pnpm lint", "vitest run", "eslint ."):
            self.assertIn(body, got)

    def test_two_levels_down_and_no_more(self):
        got = scan.with_scripts("pnpm a", self.SCRIPTS)
        self.assertIn("pnpm b", got)
        self.assertIn("pnpm c", got)
        self.assertNotIn("tsc", got)

    def test_other_runners_and_script_names(self):
        got = scan.with_scripts("npm run test:unit\nyarn lint", {"test:unit": "jest", "lint": "eslint"})
        self.assertIn("jest", got)
        self.assertIn("eslint", got)

    def test_nothing_to_append(self):
        self.assertEqual(scan.with_scripts("pnpm build", {"test": "vitest"}), "pnpm build")
        self.assertEqual(scan.with_scripts("pnpm test", {}), "pnpm test")
        self.assertEqual(scan.with_scripts("echo hi", self.SCRIPTS), "echo hi")

    def test_a_script_that_calls_itself_ends(self):
        self.assertEqual(scan.with_scripts("pnpm a", {"a": "pnpm a"}), "pnpm a\npnpm a")


# the files of one snapshot, by oid
BLOBS = {
    "w1": (
        "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - run: pnpm test\n"
        "      - run: pnpm lint\n      - uses: Gitleaks/gitleaks-action@v2\n"
    ),
    "pkg": '{"devDependencies": {"vitest": "^2", "typescript": "^5", "@biomejs/biome": "1", "husky": "9"}}',
    "py": "[tool.ruff]\nline-length = 100\n[tool.pytest.ini_options]\n",
    "pnpm": "packages:\n  - a\nminimumReleaseAge: 1440\ntrustPolicy: no-downgrade\n",
    "npmrc": "ignore-scripts=true\n",
    "dep": "version: 2\nupdates:\n  - package-ecosystem: npm\n    cooldown:\n      default-days: 7\n",
    "husky": "pnpm typecheck\ngitleaks protect --staged\n",
    "say": "# Project\n\nRun `pnpm test` before committing.\n\n## Security\n\nNever commit secrets.\n",
    "settings": json.dumps(
        {
            "permissions": {"allow": ["Bash(pnpm test:*)"], "deny": ["Read(./.env)"]},
            "sandbox": {"enabled": True},
            "hooks": {
                "PostToolUse": [
                    {"matcher": "Edit", "hooks": [{"type": "command", "command": "pnpm exec prettier --write"}]}
                ]
            },
        }
    ),
    "cursor": json.dumps({"version": 1, "hooks": {"beforeShellExecution": [{"command": "./guard.sh"}]}}),
    "codex": 'sandbox_mode = "workspace-write"\napproval_policy = "on-request"\n[sandbox_workspace_write]\n',
    "sec": "# Security\n\nWe receive many AI-generated reports. Please say so if you used one.\n",
}
BLOBS = {oid: text.encode() for oid, text in BLOBS.items()}


def tree(*entries, said=(), code=(3, 10)):
    return {"blobs": [(rule, path, oid, False) for rule, path, oid in entries], "said": list(said), "code": list(code)}


FULL = tree(
    ("workflows", ".github/workflows/ci.yml", "w1"),
    ("pkg_files", "package.json", "pkg"),
    ("pkg_files", "pyproject.toml", "py"),
    ("pkg_files", "pnpm-workspace.yaml", "pnpm"),
    ("pkg_files", ".npmrc", "npmrc"),
    ("dependabot", ".github/dependabot.yml", "dep"),
    ("git_hooks", ".husky/pre-commit", "husky"),
    ("shared_settings", ".claude/settings.json", "settings"),
    ("shared_settings", ".codex/config.toml", "codex"),
    ("hooks_files", ".cursor/hooks.json", "cursor"),
    ("security_md", "SECURITY.md", "sec"),
    ("workflows", ".github/workflows/gone.yml", "missing"),  # a blob that was not fetched
    said=["say", "missing-too"],
)


SCOPED = """on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
"""


class Token(unittest.TestCase):
    def scoped(self, text):
        return scan.token_scoped(scan.drop_comments(text))

    def test_at_the_top(self):
        self.assertTrue(self.scoped(SCOPED))
        for value in ("read-all", "{}", "\n  contents: write\n  id-token: write"):
            with self.subTest(value=value):
                self.assertTrue(self.scoped("on: push\npermissions: %s\njobs:\n  a:\n    steps: []\n" % value))

    def test_write_all_is_no_scope(self):
        self.assertFalse(self.scoped("on: push\npermissions: write-all\njobs:\n  a:\n    steps: []\n"))
        self.assertFalse(self.scoped(SCOPED.replace("    runs-on", "    permissions: write-all\n    runs-on")))

    def test_in_every_job(self):
        text = (
            "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    steps: []\n"
            "  b:\n    runs-on: x\n    permissions: {}\n"
        )
        self.assertTrue(self.scoped(text))
        self.assertFalse(self.scoped(text.replace("    permissions: {}\n", "")), "job b has none")

    def test_any_indent_of_the_jobs(self):
        self.assertTrue(
            self.scoped(
                "on: push\njobs:\n    a:\n        permissions:\n            contents: read\n"
                "        steps:\n            - run: echo\n"
            )
        )
        self.assertFalse(self.scoped("on: push\njobs:\n    a:\n        permissions: {}\n    b:\n        steps: []\n"))

    def test_a_key_deeper_in_a_job_is_not_its_permissions(self):
        self.assertFalse(
            self.scoped(
                "on: push\njobs:\n  a:\n    steps:\n      - uses: x/y@v1\n        with:\n          permissions: read\n"
            )
        )
        self.assertFalse(
            self.scoped("on: push\njobs:\n  a:\n    steps:\n      - run: |\n          permissions: read\n")
        )

    def test_the_jobs_end_at_the_next_key_of_the_workflow(self):
        self.assertTrue(self.scoped("on: push\njobs:\n  a:\n    permissions: {}\nenv:\n  x: 1\n"))

    def test_no_permissions_and_a_comment(self):
        self.assertFalse(self.scoped("on: push\njobs:\n  a:\n    steps: []\n"))
        self.assertFalse(self.scoped("on: push\n# permissions: read-all\njobs:\n  a:\n    steps: []\n"))
        self.assertFalse(self.scoped(""))
        self.assertTrue(self.scoped("permissions: read-all\n"), "no jobs block: the top decides")


class Checkouts(unittest.TestCase):
    def count(self, text):
        return scan.checkouts(scan.drop_comments(text))

    def test_counts(self):
        text = """jobs:
  a:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: second
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/checkout@v4
      - uses: acme/setup@v1
        with:
          persist-credentials: false
  b:
    steps:
    - name: unindented list
      uses: actions/checkout@v4
      with:
        persist-credentials: 'false'
"""
        self.assertEqual(self.count(text), [4, 2])

    def test_the_input_of_the_next_step_is_not_this_one(self):
        text = (
            "steps:\n  - uses: actions/checkout@v4\n  - uses: acme/x@v1\n    with:\n      persist-credentials: false\n"
        )
        self.assertEqual(self.count(text), [1, 0])

    def test_none(self):
        self.assertEqual(self.count("steps:\n  - run: echo\n"), [0, 0])
        self.assertEqual(self.count("steps:\n  # - uses: actions/checkout@v4\n"), [0, 0])


class Supply(unittest.TestCase):
    def test_what_a_workflow_runs_and_sets(self):
        release = (
            "on: push\npermissions: {}\njobs:\n  a:\n    permissions:\n      id-token: write\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"
            "      - run: npm publish --provenance\n      - uses: docker/build-push-action@v6\n        with:\n"
            "          sbom: true\n      - run: cargo deny check advisories\n"
        )
        got = scan.read_supply(
            [
                (".github/workflows/release.yml", release),
                (
                    ".github/workflows/ci.yml",
                    "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - run: pnpm fuzz\n",
                ),
            ],
            scripts={"fuzz": "cargo fuzz run parse"},
        )
        self.assertEqual(got, {"supply": ["audit", "fuzz", "provenance", "sbom"], "token": [2, 1], "checkout": [2, 1]})

    def test_a_step_name_or_a_comment_is_not_a_practice(self):
        text = (
            "jobs:\n  a:\n    steps:\n      - name: generate the sbom and sign with cosign sign\n        run: echo\n"
            "      # - run: npm publish --provenance\n      - run: echo ok # cargo audit\n"
        )
        self.assertEqual(scan.read_supply([("a.yml", text)])["supply"], [])

    def test_only_yaml_workflows_hold_a_token_or_a_checkout(self):
        md = "permissions: read-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        got = scan.read_supply([(".github/workflows/triage.md", md), (".github/workflows/triage.lock.yml", md)])
        self.assertEqual((got["token"], got["checkout"]), ([1, 1], [1, 0]))

    def test_a_file_saved_with_crlf(self):
        text = "on: push\r\njobs:\r\n  a:\r\n    permissions: {}\r\n    steps:\r\n      - uses: actions/checkout@v4\r\n"
        self.assertEqual(scan.read_supply([("a.yaml", text)]), {"supply": [], "token": [1, 1], "checkout": [1, 0]})

    def test_nothing(self):
        self.assertEqual(scan.read_supply([]), {"supply": [], "token": [0, 0], "checkout": [0, 0]})

    def test_read_guards_reads_them_from_the_workflows_only(self):
        blobs = {
            "w": b"jobs:\n  a:\n    steps:\n      - run: syft dir:.\n",
            "pkg": b'{"scripts": {"x": "cosign sign a"}}',
        }
        got = scan.read_guards(
            tree(("workflows", ".github/workflows/a.yml", "w"), ("pkg_files", "package.json", "pkg")), blobs
        )
        self.assertEqual((got["sec"]["supply"], got["sec"]["token"]), (["sbom"], [1, 0]))
        self.assertEqual(scan.read_guards(tree(("pkg_files", "package.json", "pkg")), blobs)["sec"]["supply"], [])


class ApiSecurity(unittest.TestCase):
    """api_signals.security() on invented answers: no network (its calls go through a stand-in for gh)."""

    ANSWERS = {
        "repos/acme/app/private-vulnerability-reporting": {"enabled": True},
        "repos/acme/app/rules/branches/main": [
            {"type": "pull_request", "ruleset_id": 7, "ruleset_source_type": "Organization"},
            {"type": "deletion"},
            {"type": "pull_request"},
        ],
        "repos/acme/app/branches/main": {"name": "main", "protected": True, "protection": {"enabled": False}},
        "repos/acme/app/security-advisories": [{"ghsa_id": "GHSA-x"}, {"ghsa_id": "GHSA-y"}],
    }

    def read(self, answers, repo=None):
        import api_signals

        def fake(path, params=None):
            got = answers.get(path)
            if isinstance(got, Exception):
                raise got
            return got

        with mock.patch.object(api_signals, "gh", fake):
            return api_signals.security(repo or {"name": "acme/app", "default_branch": "main"})

    def test_every_setting(self):
        self.assertEqual(
            self.read(self.ANSWERS),
            {
                "private_reporting": True,
                "protected": True,
                "branch_rules": ["deletion", "pull_request"],
                "advisories": 2,
            },
        )

    def test_only_the_rule_types_are_kept(self):
        got = self.read(self.ANSWERS)
        self.assertNotIn("7", json.dumps(got))
        self.assertNotIn("Organization", json.dumps(got))

    def test_off_and_none_are_not_unknown(self):
        answers = dict(
            self.ANSWERS,
            **{
                "repos/acme/app/private-vulnerability-reporting": {"enabled": False},
                "repos/acme/app/rules/branches/main": [],
                "repos/acme/app/branches/main": {"protected": False},
                "repos/acme/app/security-advisories": [],
            },
        )
        self.assertEqual(
            self.read(answers), {"private_reporting": False, "protected": False, "branch_rules": [], "advisories": 0}
        )

    def test_a_call_that_fails_or_answers_nothing_is_null(self):
        answers = dict(
            self.ANSWERS,
            **{
                "repos/acme/app/private-vulnerability-reporting": None,
                "repos/acme/app/security-advisories": RuntimeError("gh api failed"),
            },
        )
        got = self.read(answers)
        self.assertEqual((got["private_reporting"], got["advisories"]), (None, None))
        self.assertEqual(got["branch_rules"], ["deletion", "pull_request"])
        self.assertEqual(
            self.read(self.ANSWERS, {"name": "acme/app"}),
            {"private_reporting": True, "protected": None, "branch_rules": None, "advisories": 2},
        )


def job(*lines, head="on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"):
    """A workflow of one job: its keys and steps, indented under it."""
    return head + "".join("    " + line + "\n" for line in "\n".join(lines).split("\n"))


def steps(*lines):
    return job("steps:", *("  " + line for line in "\n".join(lines).split("\n")))


# ops.ci: for every key, workflows (lowercased, as read_guards hands them) that set it, and near misses that do not
OPS = {
    "concurrency": (
        [job("concurrency:", "  group: x", "  cancel-in-progress: true")],
        [job("concurrency:", "  group: x", "  cancel-in-progress: false"), steps("- run: echo cancel-in-progress")],
    ),
    "timeouts": ([job("timeout-minutes: 20")], [steps("- run: sleep 20 # timeout-minutes: 5")]),
    "matrix": (
        [job("strategy:", "  fail-fast: false", "  matrix:", "    node: [20, 22]")],
        [job("strategy:", "  max-parallel: 1"), steps("- run: echo ${{ matrix.node }}")],
    ),
    "cache": (
        [
            steps("- uses: actions/cache@v4", "  with:", "    path: ~/.npm"),
            steps("- uses: actions/setup-node@v4", "  with:", "    node-version: 22", "    cache: pnpm"),
            steps("- name: setup", "  uses: actions/setup-python@v5", "  with:", "    cache: pip"),
            steps("- uses: astral-sh/setup-uv@v6", "  with:", "    enable-cache: true"),
        ],
        [
            steps("- uses: actions/setup-node@v4", "  with:", "    cache: ''"),
            steps("- uses: actions/setup-go@v5", "  with:", "    cache: false"),
            # the cache input of another step is not this setup action's
            steps("- uses: actions/setup-node@v4", "- uses: acme/tool@v1", "  with:", "    cache: true"),
        ],
    ),
    "cache_docker": (
        [steps("- uses: docker/build-push-action@v6", "  with:", "    cache-from: type=gha")],
        [steps("- run: x")],
    ),
    "multi_os": (
        [
            job("strategy:", "  matrix:", "    os: [ubuntu-latest, windows-latest]"),
            job("runs-on: macos-14", head="on: push\njobs:\n  a:\n"),
            job("runs-on:", "  - macos-latest", head="on: push\njobs:\n  a:\n"),
        ],
        [
            steps("- name: build for windows-latest", "  run: echo windows-latest"),
            job("strategy:", "  matrix:", "    target: [x86_64-pc-windows-msvc]"),
            steps("- uses: acme/build@v1", "  with:", "    os: windows-latest"),
        ],
    ),
    "multi_os_any": (
        [steps("- uses: acme/build@v1", "  with:", "    os: windows-latest")],
        [steps("- name: windows-latest", "  run: |", "    echo macos-14")],
    ),
    "coverage": ([steps("- run: pnpm test", "- uses: codecov/codecov-action@v5")], [steps("- run: pnpm test")]),
    "paths_trigger": (
        [
            "on:\n  pull_request:\n    paths:\n      - 'src/**'\njobs: {}\n",
            "on:\n  push:\n    branches: [main]\n    paths-ignore: ['docs/**']\njobs: {}\n",
            "on: {push: {paths: [src]}}\njobs: {}\n",
        ],
        [
            "on:\n  workflow_dispatch:\n    inputs:\n      paths:\n        type: string\njobs: {}\n",
            steps("- uses: actions/checkout@v4", "  with:", "    sparse-checkout: |", "      paths: x"),
        ],
    ),
    "paths_action": ([steps("- uses: tj-actions/changed-files@v46")], [steps("- run: git diff --name-only")]),
    "affected": ([steps("- run: npx nx affected -t test")], [steps("- run: npx nx run-many -t test")]),
    "affected_filter": (
        [steps('- run: pnpm --filter "...[origin/main]" test')],
        [steps("- run: pnpm --filter web test")],
    ),
    "services": (
        [job("services:", "  postgres:", "    image: postgres:16")],
        [steps("- uses: acme/tool@v1", "  with:", "    services: db")],
    ),
    "merge_group": (
        ["on:\n  pull_request:\n  merge_group:\njobs: {}\n", "on: [push, merge_group]\njobs: {}\n"],
        ["on: push\njobs:\n  a:\n    if: github.event_name != 'merge_group'\n"],
    ),
    "spellcheck": ([steps("- uses: crate-ci/typos@v1.29.0")], [steps("- run: echo fix typos")]),
    "actionlint": ([steps("- run: actionlint")], [steps("- run: echo lint")]),
    "app_token": ([steps("- uses: actions/create-github-app-token@v2")], [steps("- uses: actions/checkout@v4")]),
    "release": (
        [steps("- run: gh release create v1 dist/*"), steps("- uses: changesets/action@v1")],
        ["on:\n  release:\n    types: [published]\njobs:\n  a:\n    steps:\n      - run: npm publish\n"],
    ),
    "release_draft": ([steps("- uses: release-drafter/release-drafter@v6")], [steps("- run: gh release create v1")]),
    "release_trigger": (
        [
            "on:\n  release:\n    types: [published]\njobs: {}\n",
            "on: release\njobs: {}\n",
            "on:\n  - push\n  - release\n",
        ],
        [
            "on:\n  push:\n    branches: [release]\njobs: {}\n",
            "on:\n  workflow_dispatch:\n    inputs:\n      release:\n        type: boolean\njobs: {}\n",
        ],
    ),
    "image_push": (
        [
            steps("- uses: docker/build-push-action@v6", "  with:", "    push: true", "    tags: x"),
            steps(
                "- name: build",
                "  uses: docker/build-push-action@v6",
                "  with:",
                "    push: ${{ github.ref == 'main' }}",
            ),
            steps("- run: |", "    docker buildx build \\", "      --platform linux/amd64 \\", "      --push ."),
            steps("- run: docker push ghcr.io/acme/app"),
        ],
        [
            steps("- uses: docker/build-push-action@v6", "  with:", "    push: false"),
            steps("- uses: docker/build-push-action@v6", "  with:", "    load: true"),
            # the push input of the next step is not the build's
            steps("- uses: docker/build-push-action@v6", "- uses: acme/git-push@v1", "  with:", "    push: true"),
        ],
    ),
    "image_build": ([steps("- uses: docker/build-push-action@v6")], [steps("- uses: docker/login-action@v3")]),
    "multi_arch": (
        [
            steps("- uses: docker/setup-qemu-action@v3"),
            steps("- uses: docker/build-push-action@v6", "  with:", "    platforms: linux/amd64,linux/arm64"),
            steps(
                "- uses: docker/build-push-action@v6",
                "  with:",
                "    platforms: |",
                "      linux/amd64",
                "      linux/arm64",
            ),
            job("strategy:", "  matrix:", "    platform: [linux/amd64, linux/arm64]"),
        ],
        [
            steps("- uses: docker/build-push-action@v6", "  with:", "    platforms: linux/amd64"),
            job("strategy:", "  matrix:", "    platform: [ubuntu, arm64]"),
            steps("- run: echo arm64"),
        ],
    ),
    "environment": (
        [job("environment: production"), job("environment:", "  name: pypi", "  url: https://pypi.org/p/x")],
        [steps("- uses: acme/deploy@v1", "  with:", "    environment: production"), job("env:", "  a: b")],
    ),
    "deploy": (
        [
            steps("- run: npx wrangler deploy"),
            steps("- uses: superfly/flyctl-actions@1.5", "  with:", "    args: deploy --remote-only"),
            steps("- uses: pulumi/actions@v6", "  with:", "    command: up", "    stack-name: prod"),
        ],
        [
            steps("- uses: aws-actions/configure-aws-credentials@v4"),
            steps("- uses: superfly/flyctl-actions/setup-flyctl@master"),
            steps("- uses: pulumi/actions@v6", "  with:", "    command: preview"),
        ],
    ),
    "deploy_k8s": (
        [steps("- run: kubectl apply -f k8s/")],
        [steps("- run: kubectl get pods"), steps('- run: echo "helm upgrade --install app ./chart"')],
    ),
    "deploy_s3": ([steps("- run: aws s3 sync dist s3://b")], [steps("- run: aws s3 ls")]),
    "deploy_other": (
        [steps("- run: firebase deploy"), steps("- uses: pulumi/actions@v6", "  with:", "    command: up")],
        [steps("- run: kubectl apply -f k8s/")],
    ),
    "deploy_pages": ([steps("- uses: actions/deploy-pages@v4")], [steps("- uses: actions/upload-pages-artifact@v3")]),
    "cloud_login": ([steps("- uses: azure/login@v2")], [steps("- uses: docker/login-action@v3")]),
    "publish": (
        [
            steps("- run: npm publish --provenance"),
            steps("- run: pnpm release"),  # a script of the root package.json that publishes
            steps("- uses: changesets/action@v1", "  with:", "    publish: pnpm release"),
        ],
        [steps("- run: npm publish --dry-run"), steps("- run: pnpm build")],
    ),
    "publish_script": ([steps("- run: pnpm run publish-script")], [steps("- run: npm publish")]),
    "deploy_script": ([steps("- run: pnpm exec tsx internal/scripts/deploy-dotcom.ts")], [steps("- run: echo deploy")]),
    "stale": ([steps("- uses: actions/stale@v9")], [steps("- run: echo stale")]),
    "labeler": ([steps("- uses: actions/labeler@v5")], [steps("- uses: actions/stale@v9")]),
    "title_check": ([steps("- uses: acme/action-semantic-pull-request@v5")], [steps("- run: pnpm lint")]),
}
OPS_SCRIPTS = {"release": "changeset publish", "build": "tsc"}


class Ops(unittest.TestCase):
    def test_every_key_has_examples(self):
        self.assertEqual(set(OPS), set(fp.OPS_RUN) | set(fp.OPS_TEXT) | set(scan.OPS_SHAPE))

    def test_each_key_is_set_by_its_workflows_and_not_by_its_near_misses(self):
        for key, (hits, misses) in OPS.items():
            for text in hits:
                with self.subTest(key=key, text=text):
                    self.assertIn(key, scan.read_ops([text.lower()], OPS_SCRIPTS)["ci"])
            for text in misses:
                with self.subTest(key=key, miss=text):
                    self.assertNotIn(key, scan.read_ops([text.lower()], OPS_SCRIPTS)["ci"])

    def test_a_comment_sets_nothing(self):
        text = "on: [push, merge_group]\n" + steps("- run: echo")
        commented = "\n".join("# " + line for line in text.split("\n")) + "\n" + steps("# - uses: actions/stale@v9")
        self.assertEqual(scan.read_ops([commented]), {"ci": [], "pkg": []})

    def test_a_file_saved_with_crlf(self):
        text = job("timeout-minutes: 5", "services:", "  db:", "    image: x").replace("\n", "\r\n")
        self.assertEqual(scan.read_ops([text])["ci"], ["services", "timeouts"])

    def test_keys_are_summed_over_workflows(self):
        got = scan.read_ops([steps("- uses: actions/stale@v9"), steps("- uses: actions/labeler@v5")])
        self.assertEqual(got, {"ci": ["labeler", "stale"], "pkg": []})

    def test_nothing(self):
        self.assertEqual(scan.read_ops([]), {"ci": [], "pkg": []})

    def test_the_package_json(self):
        for pkg, keys in (
            ({"prettier": "@acme/prettier-config"}, ["prettier"]),
            (
                {"devDependencies": {"prettier": "3", "lint-staged": "15", "@commitlint/cli": "19"}},
                ["commitlint", "lint_staged", "prettier"],
            ),
            ({"dependencies": {"patch-package": "8"}}, ["patches"]),
            ({"patchedDependencies": {"a@1": "patches/a.patch"}}, ["patches"]),
            ({"pnpm": {"patchedDependencies": {"a@1": "patches/a.patch"}}}, ["patches"]),
            ({"lint-staged": {"*.ts": "eslint"}}, ["lint_staged"]),
            ({"config": {"commitizen": {"path": "cz-conventional-changelog"}}}, ["commitizen"]),
            ({"scripts": {"prettier": "prettier --write .", "commitlint": "commitlint"}}, []),
            ({"devDependencies": {"@commitlint/config-conventional": "19", "prettier-plugin-x": "1"}}, []),
            ({"pnpm": "not a mapping", "dependencies": ["patch-package"]}, []),
            (None, []),
            (["prettier"], []),
        ):
            with self.subTest(pkg=pkg):
                self.assertEqual(scan.read_ops([], pkg=pkg)["pkg"], keys)

    def test_read_guards_reads_them_beside_the_checks_and_the_security(self):
        blobs = {
            "w": steps("- uses: actions/stale@v9", "- run: pnpm release").encode(),
            "pkg": b'{"scripts": {"release": "changeset publish"}, "devDependencies": {"Prettier": "3", "lint-staged": "1"}}',
        }
        got = scan.read_guards(
            tree(("workflows", ".github/workflows/a.yml", "w"), ("pkg_files", "package.json", "pkg")), blobs
        )
        self.assertEqual(
            got["ops"], {"ci": ["publish", "stale"], "pkg": ["lint_staged"]}
        )  # a name is matched as written
        self.assertEqual(scan.read_guards(tree(), {})["ops"], {"ci": [], "pkg": []})
        self.assertEqual(json.loads(json.dumps(got)), got)

    def test_hostile_texts_are_read_fast(self):
        texts = dict(
            test_fingerprints.Hostile.TEXTS,
            **{
                "sibling uses": "jobs:\n  a:\n" + "    uses: acme/setup-x@v1\n" * 20000,
                "nested keys": "on:\n" + "".join("  " * i + "a:\n" for i in range(1, 400)),
                "many platforms": "    platforms: linux/amd64\n" * 20000,
                "a long line": "jobs:\n  a:\n    runs-on: " + "windows " * 20000 + "\n",
            },
        )
        for label, text in texts.items():
            with self.subTest(text=label):
                start = time.perf_counter()
                scan.read_ops([text.lower()], {"x": text.lower()})
                self.assertLess(time.perf_counter() - start, 2.0, label)


class Shape(unittest.TestCase):
    def test_triggers(self):
        text = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n    inputs:\n      release:\njobs: {}\n"
        got = scan.triggers(text)
        self.assertEqual(set(got), {"push", "pull_request", "workflow_dispatch"})
        self.assertEqual(got["push"], "\nbranches: [main]")
        self.assertEqual(set(scan.triggers("on: [push, release]\n")), {"push", "release"})
        self.assertEqual(set(scan.triggers("on:\n  - push\n  - merge_group\n")), {"push", "merge_group"})
        self.assertEqual(scan.triggers("jobs: {}\n"), {})

    def test_job_keys(self):
        text = (
            "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        os: [x]\n    steps:\n"
            "      - run: echo\n  b:\n    uses: ./.github/workflows/c.yml\nenv:\n  services: x\n"
        )
        got = scan.job_keys(text)
        self.assertEqual([sorted(j) for j in got], [["runs-on", "steps", "strategy"], ["uses"]])
        self.assertEqual(got[0]["strategy"], ["", "matrix:", "os: [x]"])
        self.assertEqual(scan.job_keys("on: push\n"), [])

    def test_steps_using(self):
        text = steps(
            "- uses: acme/a@v1",
            "  with:",
            "    x: 1",
            "- name: b",
            "  if: always()",
            "  uses: acme/b@v1",
            "  with:",
            "    y: 2",
            "- run: echo",
        )
        got = list(scan.steps_using(text))
        self.assertEqual([a for a, _ in got], ["acme/a@v1", "acme/b@v1"])
        self.assertIn("x: 1", got[0][1])
        self.assertNotIn("name: b", got[0][1])
        self.assertIn("name: b", got[1][1])
        self.assertIn("y: 2", got[1][1])
        self.assertNotIn("run: echo", got[1][1])
        # a job that calls a reusable workflow: its inputs beside it, not the next job
        text = "jobs:\n  a:\n    uses: acme/w/.github/workflows/x.yml@v1\n    with:\n      push: true\n  b:\n    runs-on: x\n"
        ((_, step),) = scan.steps_using(text)
        self.assertIn("push: true", step)
        self.assertNotIn("runs-on", step)


class HeadPaths(unittest.TestCase):
    def test_the_paths_of_issue_1_come_last(self):
        paths = [
            ("changelog", "CHANGELOG.md"),
            ("claude_md", "CLAUDE.md"),
            ("compose", "compose.yml"),
            ("workflows", "a.yml"),
        ]
        self.assertEqual(
            scan.head_paths(paths),
            [
                ("claude_md", "CLAUDE.md"),
                ("workflows", "a.yml"),
                ("changelog", "CHANGELOG.md"),
                ("compose", "compose.yml"),
            ],
        )
        self.assertEqual(scan.head_paths(paths, cap=2), [("claude_md", "CLAUDE.md"), ("workflows", "a.yml")])

    def test_every_rule_of_issue_1_is_a_rule(self):
        self.assertLessEqual(fp.ISSUE1_RULES, set(fp.RULES))


class Guards(unittest.TestCase):
    def test_every_signal(self):
        got = scan.read_guards(FULL, BLOBS)
        self.assertEqual(
            got["checks"],
            {
                "ci": ["lint", "tests"],
                "tools": ["biome", "husky", "pytest", "ruff", "typescript", "vitest"],
                "hooks": {"checks": ["format"], "guard": 1, "setup": 0, "other": 0},
                "git": ["secrets", "types"],
                "says": ["secrets", "security", "tests"],
                "code": [3, 10],
            },
        )
        self.assertEqual(
            got["sec"],
            {
                "scanners": ["gitleaks"],
                "pins": [0, 2, 0, 1],
                "agent": None,
                "cooldown": ["dependabot", "pnpm"],
                "pm": ["no_scripts", "trust_policy"],
                "perms": {
                    "allow": 1,
                    "deny": 1,
                    "ask": 0,
                    "secrets": True,
                    "sandbox": True,
                    "no_bypass": False,
                    "mcp_all": False,
                },
                "codex": {"sandbox": "workspace-write", "approval": "on-request", "writable": True},
                "policy_ai": True,
                "manager": None,
                # ci.yml: no permissions key, one checkout that keeps its token; gone.yml was not fetched
                "supply": [],
                "token": [1, 0],
                "checkout": [1, 0],
            },
        )

    def test_the_result_is_json(self):
        got = scan.read_guards(FULL, BLOBS)
        self.assertEqual(json.loads(json.dumps(got)), got)

    def test_an_empty_snapshot(self):
        got = scan.read_guards(tree(code=(0, 0)), {})
        self.assertEqual(got["checks"], {"ci": [], "tools": [], "hooks": None, "git": [], "says": [], "code": [0, 0]})
        self.assertEqual(
            got["sec"],
            {
                "scanners": [],
                "pins": [0, 0, 0, 0],
                "agent": None,
                "cooldown": [],
                "pm": [],
                "perms": None,
                "codex": None,
                "policy_ai": False,
                "manager": None,
                "supply": [],
                "token": [0, 0],
                "checkout": [0, 0],
            },
        )
        json.dumps(got)

    def test_a_missing_blob_is_skipped(self):
        only_missing = tree(
            ("workflows", "w.yml", "nope"),
            ("pkg_files", "package.json", "nope2"),
            ("security_md", "SECURITY.md", "nope3"),
            said=["nope4"],
        )
        self.assertEqual(scan.read_guards(only_missing, BLOBS), scan.read_guards(tree(), {}))
        self.assertEqual(
            scan.read_guards(FULL, {k: v for k, v in BLOBS.items() if k != "pkg"})["checks"]["tools"],
            ["pytest", "ruff"],
        )

    def test_only_the_root_package_files_name_tools(self):
        got = scan.read_guards(tree(("pkg_files", "package.json", "pkg"), ("pkg_files", "pyproject.toml", "py")), BLOBS)
        self.assertEqual(got["checks"]["tools"], ["biome", "husky", "pytest", "ruff", "typescript", "vitest"])
        # a tool named in the wrong file is not read
        swapped = scan.read_guards(
            tree(("pkg_files", "package.json", "py"), ("pkg_files", "pyproject.toml", "pkg")), BLOBS
        )
        self.assertEqual(swapped["checks"]["tools"], [])

    def test_the_root_settings_file_wins(self):
        nested = json.dumps({"permissions": {"deny": ["Read(./.env)", "Read(./secrets/**)"]}}).encode()
        for order in (("nested", "root"), ("root", "nested")):
            entries = [
                ("shared_settings", "app/.claude/settings.json" if k == "nested" else ".claude/settings.json", k)
                for k in order
            ]
            got = scan.read_guards(tree(*entries), dict(BLOBS, nested=nested, root=BLOBS["settings"]))
            with self.subTest(order=order):
                self.assertEqual(got["sec"]["perms"]["deny"], 1)

    def test_settings_that_do_not_parse_are_skipped(self):
        got = scan.read_guards(tree(("shared_settings", ".claude/settings.json", "bad")), {"bad": b"not json"})
        self.assertIsNone(got["sec"]["perms"])
        self.assertIsNone(got["checks"]["hooks"])

    def test_a_workflow_that_calls_an_agent(self):
        got = scan.read_guards(
            tree(("workflows", "a.yml", "agent"), ("workflows", "b.yml", "target")),
            {"agent": AGENT.encode(), "target": NO_AGENT_TARGET.encode()},
        )
        self.assertEqual(got["sec"]["agent"], {"n": 1, "fence": ["bash", "bots", "tools"]})

    def test_the_workflow_text_is_lowercased_before_it_is_read(self):
        text = (
            "on: issue_comment\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n"
            "          allowed_tools: |\n            Read\n            Bash\n      - run: PNPM LINT\n"
        )
        got = scan.read_guards(tree(("workflows", "a.yml", "w")), {"w": text.encode()})
        self.assertEqual(got["sec"]["agent"], {"n": 1, "fence": ["bash", "tools"]})
        self.assertEqual(got["checks"]["ci"], ["lint"])

    def test_an_action_of_the_repos_own_account_is_not_third_party(self):
        blobs = {"w": b"steps:\n  - uses: Acme/tool@v1\n  - uses: other/x@v1\n"}
        t = tree(("workflows", "a.yml", "w"))
        self.assertEqual(scan.read_guards(t, blobs)["sec"]["pins"], [0, 2, 0, 2])
        self.assertEqual(scan.read_guards(t, blobs, "acme")["sec"]["pins"], [0, 2, 0, 1])

    def test_a_workflow_calls_a_script_of_the_root_package_json(self):
        pkg = json.dumps({"scripts": {"Verify": "Vitest run && ESLint .", "dev": "vite"}}).encode()
        t = tree(("workflows", "a.yml", "w"), ("pkg_files", "package.json", "pkg"))
        got = scan.read_guards(t, {"w": b"steps:\n  - run: pnpm verify\n", "pkg": pkg})
        self.assertEqual(got["checks"]["ci"], ["lint", "tests"])
        # the scripts of a package.json that is not the root one are not read
        nested = tree(("workflows", "a.yml", "w"), ("pkg_files", "packages/a/package.json", "pkg"))
        self.assertEqual(
            scan.read_guards(nested, {"w": b"steps:\n  - run: pnpm verify\n", "pkg": pkg})["checks"]["ci"], []
        )
        # a package.json that has no scripts, or does not parse, changes nothing
        for raw in (b"{}", b"not json", b'{"scripts": []}'):
            t = tree(("workflows", "a.yml", "w"), ("pkg_files", "package.json", "pkg"))
            self.assertEqual(
                scan.read_guards(t, {"w": b"steps:\n  - run: pnpm verify\n", "pkg": raw})["checks"]["ci"], []
            )

    def test_git_hooks_are_read_without_comments_and_commitlint(self):
        hooks = {
            "a": b"#!/bin/sh\n# run pytest and eslint here\nnpx --no -- commitlint --edit $1\n",
            "b": b"#!/bin/sh\npnpm exec vitest related --run\n# tsc is slow\n",
            "c": b"repos:\n  - repo: local\n    hooks:\n      - id: x\n        entry: uv run pytest\n"
            b"        args: [--pytest-test-first]\n        additional_dependencies: [pytest]\n",
        }
        self.assertEqual(scan.read_guards(tree(("git_hooks", ".husky/commit-msg", "a")), hooks)["checks"]["git"], [])
        self.assertEqual(
            scan.read_guards(tree(("git_hooks", ".husky/pre-commit", "b")), hooks)["checks"]["git"], ["tests"]
        )
        self.assertEqual(
            scan.read_guards(tree(("git_hooks", ".pre-commit-config.yaml", "c")), hooks)["checks"]["git"], ["tests"]
        )
        # the hook files of a repo are read together
        both = tree(("git_hooks", ".husky/commit-msg", "a"), ("git_hooks", ".husky/pre-commit", "b"))
        self.assertEqual(scan.read_guards(both, hooks)["checks"]["git"], ["tests"])

    def test_a_nested_package_manager_file_is_read_with_the_root_one_of_its_name(self):
        blobs = {
            "root": b"registry=https://example.com\n",
            "ui": b"minimum-release-age=1440\n",
            "ws": b"packages:\n  - a\n",
            "uiws": b"minimumReleaseAge: 1440\ntrustPolicy: no-downgrade\n",
        }
        self.assertEqual(scan.read_guards(tree(("pkg_files", ".npmrc", "root")), blobs)["sec"]["cooldown"], [])
        got = scan.read_guards(tree(("pkg_files", ".npmrc", "root"), ("pkg_nested", "ui/.npmrc", "ui")), blobs)
        self.assertEqual(got["sec"]["cooldown"], ["pnpm"])
        got = scan.read_guards(tree(("pkg_nested", "apps/web/pnpm-workspace.yaml", "uiws")), blobs)
        self.assertEqual(got["sec"]["cooldown"], ["pnpm"])
        self.assertEqual(got["sec"]["pm"], ["trust_policy"])
        # a nested package.json is not read: only the root names the tools
        self.assertEqual(
            scan.read_guards(tree(("pkg_nested", "ui/package.json", "root")), blobs)["checks"]["tools"], []
        )

    def test_the_package_manager_is_the_one_the_root_package_json_pins(self):
        def pkg(v):
            return tree(("pkg_files", "package.json", "p")), {"p": ('{"packageManager": "%s"}' % v).encode()}

        for pinned, expected in (
            ("pnpm@11.2.0", ["pnpm", 11, 2]),
            ("yarn@4.15.1+sha512.abc", ["yarn", 4, 15]),
            ("bun@1.2.3", ["bun", 1, 2]),
            ("npm@10.8.2", ["npm", 10, 8]),
            ("pnpm", None),
            ("pnpm@11", None),
            ("deno@2.0.0", None),
        ):
            with self.subTest(pinned=pinned):
                t, blobs = pkg(pinned)
                self.assertEqual(scan.read_guards(t, blobs)["sec"]["manager"], expected)
        t, blobs = pkg("pnpm@11.2.0")
        self.assertEqual(json.loads(json.dumps(scan.read_guards(t, blobs))), scan.read_guards(t, blobs))
        self.assertIsNone(scan.read_guards(tree(("pkg_files", "pyproject.toml", "p")), blobs)["sec"]["manager"])

    def test_the_instruction_files_say_through_instructions_say(self):
        text = b"Use `vitest`. Run pnpm lint. Never commit credentials.\n## Security\nSee jest.config.js and mypy (partial)."
        got = scan.read_guards(tree(said=["a"]), {"a": text})["checks"]["says"]
        self.assertEqual(got, ["lint", "secrets", "security", "tests"])

    def test_instruction_files_are_read_as_written(self):
        got = scan.read_guards(tree(said=["a"]), {"a": b"Run PNPM TEST. ## not a heading"})
        self.assertEqual(got["checks"]["says"], ["tests"])


class Tree(unittest.TestCase):
    """read_tree on a tiny git repo built in a temp dir (its own repo: nothing touches this one)."""

    def commit(self, paths):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        for path in paths:
            full = os.path.join(d.name, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write("x")
        # Without the GIT_* variables: inside a hook git exports GIT_DIR, and with it every command below, and the
        # reader itself, would act on the repo that runs the hook, not on the temp one (it did once: six
        # commits on the branch being pushed).
        clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        with mock.patch.dict(os.environ, clean, clear=True):
            env = dict(clean, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
            git = [
                "git",
                "-C",
                d.name,
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
            ]
            subprocess.run(git + ["init", "-q"], check=True, capture_output=True, env=env)
            top = (
                subprocess.run(git + ["rev-parse", "--absolute-git-dir"], check=True, capture_output=True, env=env)
                .stdout.decode()
                .strip()
            )
            self.assertEqual(
                os.path.realpath(top),
                os.path.realpath(os.path.join(d.name, ".git")),
                "the commit would not go to the temp repo",
            )
            for args in (["add", "-A"], ["commit", "-q", "-m", "x"]):
                subprocess.run(git + args, check=True, capture_output=True, env=env)
            sha = (
                subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, env=env)
                .stdout.decode()
                .strip()
            )
            return scan.read_tree(d.name, sha)

    def test_the_lint_files_of_a_released_plugin_are_shipped(self):
        got = self.commit(
            [
                "tools/eslint-plugin-foo/CHANGELOG.md",
                "tools/eslint-plugin-foo/rules/a.js",
                "tools/eslint-plugin-foo/rules/b.ts",
                "tools/eslint-plugin-foo/README.md",
                "other/eslint-plugin-bar/LICENSE",
                "other/eslint-plugin-bar/lib/c.js",
                "eslint-rules/x.js",
                "other/eslint-rules/y.js",
                "eslint-plugin-baz/rules/z.js",
            ]
        )
        lint = got["hits"]["custom_lint"]
        # released: a changelog or a licence at the plugin's root. Its rule files are the product's
        self.assertEqual(lint["shipped"], 3)
        self.assertEqual(lint["n"], 3)
        self.assertEqual(
            sorted(lint["sample"]), ["eslint-plugin-baz/rules/z.js", "eslint-rules/x.js", "other/eslint-rules/y.js"]
        )
        self.assertEqual(lint["root"], 2)
        self.assertEqual(sorted(path for rule, path in got["paths"] if rule == "custom_lint"), sorted(lint["sample"]))

    def test_a_rule_whose_file_names_may_name_a_person_is_counted_and_never_kept(self):
        """A change note named for its author, a patch of a package on a person's scope (fp.UNSTORED): counted, with no
        path in a sample or in the paths the tip keeps."""
        self.assertEqual(fp.UNSTORED, {"changelog_dir", "patches"})
        got = self.commit(
            ["changelog/someone_fix-a-bug.md", "changelog/other_add-b.md", "patches/@scope__pkg@1.2.3.patch"]
        )
        for rule, n in (("changelog_dir", 2), ("patches", 1)):
            self.assertEqual(
                (got["hits"][rule]["n"], got["hits"][rule]["root"], got["hits"][rule]["sample"]), (n, n, [])
            )
        self.assertEqual([p for p in got["paths"] if p[0] in fp.UNSTORED], [])

    def test_a_released_plugin_is_found_whatever_the_case_of_its_folder(self):
        got = self.commit(
            [
                "Pkg/ESLint-Plugin/CHANGELOG.md",
                "Pkg/ESLint-Plugin/rules/a.js",
                "Pkg/ESLint-Plugin/src/b.ts",
                "Other/OXLINT-PLUGINS-Foo/LICENSE",
                "Other/OXLINT-PLUGINS-Foo/rules/c.js",
                "Other/Biome-Plugin/.NPMIGNORE",
                "Other/Biome-Plugin/x.grit",
                "Rules/eslint-rules/d.js",
            ]
        )
        lint = got["hits"]["custom_lint"]
        self.assertEqual(lint["shipped"], 4)
        self.assertEqual(lint["sample"], ["Rules/eslint-rules/d.js"])
        self.assertEqual(lint["n"], 1)

    def test_a_plugin_that_is_not_released_is_counted(self):
        got = self.commit(
            ["eslint-plugin-foo/README.md", "eslint-plugin-foo/package.json", "eslint-plugin-foo/rules/a.js"]
        )
        self.assertEqual(got["hits"]["custom_lint"]["n"], 1)
        self.assertEqual(got["hits"]["custom_lint"]["shipped"], 0)

    def test_a_changelog_elsewhere_releases_nothing(self):
        got = self.commit(["CHANGELOG.md", "eslint-rules/CHANGELOG.md", "eslint-rules/a.js", "docs/LICENSE"])
        self.assertEqual(got["hits"]["custom_lint"]["n"], 1)
        self.assertEqual(got["hits"]["custom_lint"]["shipped"], 0)

    def test_the_other_rules_are_read_as_before(self):
        got = self.commit(
            [
                "CLAUDE.md",
                "package.json",
                "ui/.npmrc",
                ".husky/pre-commit",
                "sandbox/vitest.config.ts",
                "src/a.ts",
                "src/a.test.ts",
                "build/gen.js",
                "web/build/app.js",
                ".claude/hooks/pre-commit",
            ]
        )
        hits = got["hits"]
        self.assertEqual(hits["claude_md"]["n"], 1)
        self.assertEqual((hits["pkg_files"]["n"], hits["pkg_nested"]["n"]), (1, 1))
        self.assertEqual(hits["git_hooks"]["n"], 1)  # the agent's hook is not a git hook
        self.assertEqual((hits["vitest"]["n"], hits["vitest"]["shipped"]), (0, 1))  # sandbox/ is shipped for the checks
        # own code: src/a.ts, src/a.test.ts, web/build/app.js and the vitest config; build/ at the root is output
        self.assertEqual(got["code"], [1, 4])
        self.assertEqual({blob[0] for blob in got["blobs"]}, {"pkg_files", "pkg_nested", "git_hooks", "claude_md"})

    def test_the_root_and_the_files(self):
        got = self.commit(["a.txt", "dir/b.txt"])
        self.assertEqual((got["root"], got["n_files"]), (["a.txt", "dir"], 2))


class Wanted(unittest.TestCase):
    def setUp(self):
        self.trees = {
            "A": tree(
                ("workflows", "w", "wA"),
                ("shared_settings", ".claude/settings.json", "sA"),
                ("pkg_files", "package.json", "pA"),
                ("hooks_files", ".cursor/hooks.json", "hA"),
                ("claude_md", "CLAUDE.md", "iA"),
                ("agents_md", "AGENTS.md", "iA2"),
                said=["iA2"],
            ),
            "B": tree(
                ("workflows", "w", "wB"),
                ("pkg_files", "package.json", "pB"),
                ("shared_settings", ".claude/settings.json", "sB"),
                ("security_md", "SECURITY.md", "mB"),
                ("git_hooks", ".husky/pre-commit", "gB"),
                ("claude_md", "CLAUDE.md", "iB"),
                said=["iB"],
            ),
        }
        self.picked = [None, ("A", "A", False), ("B", "B", False)]

    def test_order(self):
        got = scan.wanted_blobs(self.picked, self.trees)
        self.assertEqual(
            got,
            [
                "wB",
                "pB",
                "sB",
                "mB",
                "gB",
                "iB",  # the last snapshot, all of it
                "wA",
                "sA",  # older ones: what the first scans read
                "pA",
                "hA",
                "iA2",
            ],
        )  # then what only the guards read
        self.assertNotIn("iA", got)  # an instruction file that is not a root one

    def test_the_first_scan_blobs_come_before_the_guards_only_blobs(self):
        got = scan.wanted_blobs(self.picked, self.trees)
        first = {oid for t in self.trees.values() for rule, _, oid, _ in t["blobs"] if rule in scan.CONTENT_RULES}
        guards_only = {"pA", "hA", "iA2"}
        self.assertLess(max(got.index(o) for o in first), min(got.index(o) for o in guards_only))

    def test_every_blob_of_the_last_snapshot_is_wanted(self):
        got = scan.wanted_blobs(self.picked, self.trees)
        self.assertLessEqual({oid for _, _, oid, _ in self.trees["B"]["blobs"]}, set(got))

    def test_newest_first(self):
        got = scan.wanted_blobs(self.picked, self.trees)
        self.assertLess(got.index("wB"), got.index("wA"))
        self.assertLess(got.index("pB"), got.index("pA"))

    def test_no_duplicate(self):
        picked = [("A", "A", False), ("A", "A", False), ("B", "B", False), ("B", "B", False)]
        trees = {k: dict(v, blobs=v["blobs"] + [("workflows", "w2", "wB", False)]) for k, v in self.trees.items()}
        got = scan.wanted_blobs(picked, trees)
        self.assertEqual(len(got), len(set(got)))
        self.assertIn("wB", got)

    def test_a_snapshot_that_is_none_is_skipped(self):
        self.assertEqual(
            scan.wanted_blobs([None, None, ("B", "B", False)], self.trees), ["wB", "pB", "sB", "mB", "gB", "iB"]
        )
        self.assertEqual(scan.wanted_blobs([None, None], self.trees), [])

    def test_the_tree_is_looked_up_by_the_second_field(self):
        picked = [("commit-a", "A", False), ("commit-b", "B", False)]
        self.assertEqual(scan.wanted_blobs(picked, self.trees)[0], "wB")


class Throwaway:
    """A git repo in a temp dir, built commit by commit, as Tree.commit builds one: without the GIT_* variables, with no
    config of this machine, and checked to be the temp repo before anything is committed. Nothing touches this repo."""

    def __init__(self, case):
        d = tempfile.TemporaryDirectory()
        case.addCleanup(d.cleanup)
        self.path, self.case = d.name, case
        self.clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.run("init", "-q")
        top = self.run("rev-parse", "--absolute-git-dir").decode().strip()
        case.assertEqual(
            os.path.realpath(top),
            os.path.realpath(os.path.join(self.path, ".git")),
            "the commit would not go to the temp repo",
        )

    def run(self, *args, date=None, data=None):
        env = dict(self.clean, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        if date:
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        git = [
            "git",
            "-C",
            self.path,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ]
        with mock.patch.dict(os.environ, self.clean, clear=True):
            return subprocess.run(git + list(args), check=True, capture_output=True, env=env, input=data).stdout

    def commit(self, message, date, files=(), links=()):
        """One commit with this message, verbatim, at this date (ISO, UTC); `files` written, `links` as (path, target)."""
        for path, text in dict(files).items():
            full = os.path.join(self.path, path)
            os.makedirs(os.path.dirname(full) or self.path, exist_ok=True)
            with open(full, "wb") as f:
                f.write(text if isinstance(text, bytes) else text.encode())
        for path, target in links:
            full = os.path.join(self.path, path)
            os.makedirs(os.path.dirname(full) or self.path, exist_ok=True)
            os.symlink(target, full)
        self.run("add", "-A")
        self.run("commit", "-q", "--allow-empty", "--cleanup=verbatim", "-F", "-", date=date, data=message.encode())
        return self.run("rev-parse", "HEAD").decode().strip()


class Commits(unittest.TestCase):
    """read_commits on throwaway repos whose commit messages are hostile."""

    DATES = [scan.dt.date(2026, 11, 17)]

    def read(self, *messages):
        repo = Throwaway(self)
        for i, message in enumerate(messages):
            repo.commit(message, "2026-11-%02dT12:00:00Z" % (i + 1))
        return scan.read_commits(repo.path, self.DATES)

    def test_a_body_that_ends_a_record_does_not_end_the_scan(self):
        # the record separator of the old format, then a field that is not a timestamp: int() raised, the scan FAILED
        windows, models, bots = self.read("subject\n\nbody\x1enotanumber\x1fa\x1fb\x1fc\n", "second\n")
        self.assertEqual(windows, [{"total": 2, "signed": 0, "by": {}}])
        self.assertEqual((models, bots), ({}, {}))

    def test_a_body_cannot_add_a_commit_of_its_own(self):
        # a forged record: a date of 2023-11, an agent's identity. It added {"2023-11 claude": 1} and a signed commit
        windows, models, bots = self.read("subject\n\n\x1e1700000000\x1fclaude <noreply@anthropic.com>\x1f\x1fx\n")
        self.assertEqual(windows, [{"total": 1, "signed": 0, "by": {}}])
        self.assertEqual((models, bots), ({}, {}))

    def test_a_window_holds_the_commits_behind_its_snapshot(self):
        forged = "\x1e%d\x1fclaude <noreply@anthropic.com>\x1f\x1fx\n" % scan.end_of_day_ts(self.DATES[0])
        windows, models, _ = self.read("subject\n\n" + forged)
        self.assertEqual(windows[0]["total"], 1)
        self.assertEqual(models, {})

    def test_a_body_with_the_field_separator_is_still_read(self):
        # the body is the last field: a separator inside it does not cut it short, and what follows is still the body
        message = "subject\n\na\x1fb\n\nGenerated with Claude Code\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>\n"
        windows, models, bots = self.read(message)
        self.assertEqual(windows, [{"total": 1, "signed": 1, "by": {"claude": 1}}])
        self.assertEqual(models, {"2026-11 claude opus 4.5": 1})
        self.assertEqual(bots, {"claude opus 4.5 <noreply@anthropic.com>": 1})

    def test_plain_commits(self):
        windows, models, _ = self.read("one\n", "two\n\nCo-authored-by: Claude <noreply@anthropic.com>\n")
        self.assertEqual(windows, [{"total": 2, "signed": 1, "by": {"claude": 1}}])
        self.assertEqual(models, {"2026-11 claude": 1})


NAME = "acme/widget"


class CloneFailed(BaseException):
    """A clone of a throwaway repo that failed: an error of the test's setup, not a status of the scan to check."""


def scan_throwaway(case, remote, keep=False, tz=None, fail_fetch=False):
    """scan.scan() end to end on a throwaway repo served as its remote, over file:// in place of github.com: the real clone,
    the real fetch of blobs, the real readers. What it writes goes to a temp folder, not to data/; it returns the scan's
    status, the JSON it wrote (None if none) and that folder."""
    remote.run("config", "uploadpack.allowFilter", "true")
    remote.run("config", "uploadpack.allowAnySHA1InWant", "true")
    out = tempfile.TemporaryDirectory()
    case.addCleanup(out.cleanup)
    url = "https://github.com/%s.git" % NAME
    real_run = scan.run

    said = []  # each git call: its subcommand, exit code and error text, for a failure to say what git answered

    def run(cmd, *args, **kwargs):
        what = cmd[5] if cmd[1] == "-C" else cmd[1]  # scan.git() puts -C <repo> -c <config> first
        if fail_fetch and "fetch" in cmd and "--stdin" in cmd:  # the batch fetch of blobs, refused as a server would
            said.append((what, 128, "fatal: remote error: refused"))
            return subprocess.CompletedProcess(cmd, 128, b"", b"fatal: remote error: refused")
        p = real_run([("file://" + remote.path) if c == url else c for c in cmd], *args, **kwargs)
        said.append((what, p.returncode, p.stderr.decode(errors="replace")))
        return p

    def no_sleep(_):
        # Raised past the scan's `except Exception`, which would cut it to 200 characters and make it a status. It names who
        # slept, and every git call so far with its exit code and error text: a bare "failed: " left the cause unknown.
        caller = sys._getframe(1)
        raise CloneFailed(
            "the clone of the throwaway repo failed (sleep called from %s:%d); git said, call by call: %s"
            % (
                os.path.basename(caller.f_code.co_filename),
                caller.f_lineno,
                " | ".join("%s exit %s: %r" % (what, code, err[:300]) for what, code, err in said) or "nothing yet",
            )
        )

    # The scan's own `time`, not the module: time.sleep patched in place was also subprocess's, which sleeps while it waits for
    # a git that has closed its pipes and not yet exited (with a timeout, as scan.run sets). Under load, on this Mac and on
    # GitHub's runner, that raised in the middle of a scan whose every git call had exited 0.
    clock = types.ModuleType("time")
    clock.__dict__.update(vars(scan.time), sleep=no_sleep)
    env = dict(scan.ENV, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, **({"TZ": tz} if tz else {}))
    with mock.patch.multiple(
        scan,
        run=run,
        DATA=scan.Path(out.name),
        CLONES=scan.Path(out.name) / "clones",
        MIN_FREE_GB=0,
        ENV=env,
        time=clock,
    ):
        (scan.Path(out.name) / "clones").mkdir()
        _, status, _ = scan.scan({"name": NAME, "league": "pro", "created_at": "2024-01-01T00:00:00Z"}, keep=keep)
    path = scan.Path(out.name) / "scan" / (scan.slug(NAME) + ".json")
    return status, (json.loads(path.read_text()) if path.exists() else None), scan.Path(out.name)


class Helper(unittest.TestCase):
    """scan_throwaway itself: it stops a scan that would sleep before cloning again, and nothing else."""

    def test_a_git_slow_to_exit_after_closing_its_pipes_is_waited_for(self):
        # subprocess, waiting with a timeout, sleeps while waitpid says "not exited yet": made certain here, for every git call
        real = vars(subprocess.Popen)["_try_wait"]  # private: the one place it can be made certain

        def not_yet_once(popen, flags):
            if flags == os.WNOHANG and not getattr(popen, "_waited", False):
                popen._waited = True
                return (0, 0)
            return real(popen, flags)

        remote = Throwaway(self)
        remote.commit("tree", "2025-01-10T12:00:00Z", {"CLAUDE.md": "x\n"})
        with mock.patch.object(subprocess.Popen, "_try_wait", not_yet_once):
            status, _, _ = scan_throwaway(self, remote)
        self.assertTrue(status.startswith("ok"), status)

    def test_a_clone_that_fails_stops_the_test_with_what_git_said(self):
        empty = tempfile.TemporaryDirectory()  # no repo in it: git cannot clone it
        self.addCleanup(empty.cleanup)
        with self.assertRaises(CloneFailed) as raised:
            scan_throwaway(self, types.SimpleNamespace(path=empty.name, run=lambda *args: b""))
        self.assertRegex(
            str(raised.exception),
            r"sleep called from scan\.py:\d+\); git said, call by call: clone exit 128: .*does not appear to be a git repo",
        )


def utc(ts):
    return scan.dt.datetime.fromtimestamp(ts, scan.dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


CLAUDE = "\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n"


class History(unittest.TestCase):
    """Where a scan's history starts at the start of the first snapshot's window."""

    def test_the_history_starts_where_the_first_window_starts(self):
        dates = scan.snapshot_dates()
        edge = scan.end_of_day_ts(dates[0]) - scan.COMMIT_DAYS * 86400
        self.assertEqual(scan.SHALLOW_SINCE, utc(edge))
        self.assertEqual(
            (dates[0].isoformat(), scan.SHALLOW_SINCE), ("2025-01-17", "2024-10-19T23:59:59Z")
        )  # the grid of a run on the 17th
        # every snapshot's window starts on or after the cut: no commit it counts is before the history
        since = int(
            scan.dt.datetime.strptime(scan.SHALLOW_SINCE, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=scan.dt.timezone.utc)
            .timestamp()
        )
        self.assertEqual(since, edge)
        self.assertTrue(all(scan.end_of_day_ts(d) - scan.COMMIT_DAYS * 86400 >= since for d in dates))
        # derived, not typed: the assignment in common.py is no string
        tree = ast.parse((base.PIPELINE / "common.py").read_text())
        value = next(
            n.value
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SHALLOW_SINCE" for t in n.targets)
        )
        self.assertNotIsInstance(value, ast.Constant)

    def test_a_scan_counts_the_first_window_whole_and_says_where_it_starts(self):
        remote = Throwaway(self)
        remote.commit("old", "2024-09-01T12:00:00Z", {"a.txt": "1"})
        remote.commit("in the first window, before December" + CLAUDE, "2024-11-01T12:00:00Z", {"a.txt": "2"})
        remote.commit("in the first window" + CLAUDE, "2025-01-10T12:00:00Z", {"a.txt": "3"})
        remote.commit("in the second window", "2025-02-10T12:00:00Z", {"a.txt": "4"})
        status, got, _ = scan_throwaway(self, remote)
        self.assertTrue(status.startswith("ok since"), status)
        self.assertEqual(got["since"], scan.SHALLOW_SINCE)
        self.assertEqual(got["snaps"][0]["commits90"], {"total": 2, "signed": 2, "by": {"claude": 2}})
        self.assertEqual(
            got["snaps"][1]["commits90"], {"total": 2, "signed": 1, "by": {"claude": 1}}
        )  # from 19 November
        self.assertEqual(got["models"], {"2024-11 claude": 1, "2025-01 claude": 1})

    def test_the_edge_is_an_instant_whatever_the_local_time(self):
        """git reads a bare date as that day at the time the command runs, in local time: the cut is an instant in UTC. A commit
        one second inside the first window is in it, and one two seconds before its edge is in neither the clone nor the log,
        in a time zone 14 hours ahead of UTC and in one 12 hours behind (with a bare date, ahead of UTC the clone takes the
        commit before the edge at any hour, and behind it drops the one inside from noon on)."""
        edge = scan.end_of_day_ts(scan.snapshot_dates()[0]) - scan.COMMIT_DAYS * 86400
        for tz in ("Etc/GMT-14", "Etc/GMT+12"):
            with self.subTest(tz=tz):
                remote = Throwaway(self)
                remote.commit("before the edge" + CLAUDE, utc(edge - 2), {"a.txt": "1"})
                remote.commit("on the edge" + CLAUDE, utc(edge), {"a.txt": "2"})
                remote.commit("just inside" + CLAUDE, utc(edge + 1), {"a.txt": "3"})
                status, got, out = scan_throwaway(self, remote, keep=True, tz=tz)
                self.assertTrue(status.startswith("ok since"), status)
                clone = out / "clones" / scan.slug(NAME)
                held = (
                    subprocess.run(
                        ["git", "-C", str(clone), "log", "--format=%ct", "HEAD"],
                        check=True,
                        capture_output=True,
                        env=dict(
                            {k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
                            GIT_DIR=str(clone / ".git"),
                        ),
                    )
                    .stdout.decode()
                    .split()
                )
                self.assertEqual(sorted(map(int, held)), [edge, edge + 1])
                # the window is (edge, end of the first snapshot's day]: the commit on the edge is held, not counted
                self.assertEqual(got["snaps"][0]["commits90"], {"total": 1, "signed": 1, "by": {"claude": 1}})


class Inside(unittest.TestCase):
    """What a repo writes as a path to elsewhere is stored only when it is relative and stays inside the repo: an
    absolute path, or one that climbs out, can name a person's home folder. The names below are made up."""

    def test_inside(self):
        for path, target in (
            ("CLAUDE.md", "AGENTS.md"),
            ("CLAUDE.md", "docs/guide.md"),
            (".claude/skills", "../.agents/skills"),
            ("a/b/CLAUDE.md", "../../AGENTS.md"),
            (".claude/skills", "../skills/"),
            ("x", "./y"),
        ):
            with self.subTest(path=path, target=target):
                self.assertEqual(scan.inside(path, target), target)
        for path, target in (
            ("CLAUDE.md", "/home/ana-example/notes.md"),
            (".claude/skills", "/Users/ana-example/skills"),
            ("CLAUDE.md", "../outside.md"),
            ("a/CLAUDE.md", "../../outside.md"),
            (".claude/skills", "../.."),
            ("CLAUDE.md", "~/notes.md"),
            ("CLAUDE.md", "C:/Users/ana-example/x.md"),
            ("x", "..\\y"),
            ("x", ""),
        ):
            with self.subTest(path=path, target=target):
                self.assertIsNone(scan.inside(path, target))

    def test_an_import_that_leaves_the_repo_is_not_stored(self):
        text = "@AGENTS.md\n@docs/guide.md\n@/home/ana-example/workspace/notes.md\n@../../outside.md\n"
        head = {"blobs": [("claude_md", "CLAUDE.md", "c", False), ("claude_md", "pkg/CLAUDE.md", "p", False)]}
        blobs = {"c": text.encode(), "p": b"See @../AGENTS.md and @../../../up.md\n"}
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        with mock.patch.object(scan, "DATA", scan.Path(out.name)):
            got = scan.store_instructions(NAME, head, blobs)
        self.assertEqual([i["imports"] for i in got], [["AGENTS.md", "docs/guide.md"], ["../AGENTS.md"]])
        self.assertNotIn("ana-example", json.dumps(got))


class Links(unittest.TestCase):
    """A symlink's target is stored only when it is relative and stays inside the repo, else null: scanned end to end on a throwaway repo.
    The names are made up."""

    def test_a_target_out_of_the_repo_is_stored_as_null(self):
        remote = Throwaway(self)
        remote.commit(
            "tree",
            "2025-01-10T12:00:00Z",
            {"AGENTS.md": "# Agents\n", ".agents/skills/a/SKILL.md": "x"},
            links=[
                (".claude/skills", "/home/ana-example/skills"),
                (".cursor/skills", "../.agents/skills"),
                (".codex/skills", "../../../elsewhere/skills"),
                ("CLAUDE.md", "AGENTS.md"),
                ("pkg/CLAUDE.md", "/Users/ana-example/CLAUDE.md"),
            ],
        )
        status, got, _ = scan_throwaway(self, remote)
        self.assertTrue(status.startswith("ok"), status)
        self.assertEqual(
            sorted((l["path"], l["to"]) for l in got["links"]),
            [(".claude/skills", None), (".codex/skills", None), (".cursor/skills", "../.agents/skills")],
        )
        self.assertEqual(
            {i["path"]: i["symlink_to"] for i in got["instructions"] if "symlink_to" in i},
            {"CLAUDE.md": "AGENTS.md", "pkg/CLAUDE.md": None},
        )
        self.assertNotIn("ana-example", json.dumps(got))


class Blobs(unittest.TestCase):
    """What the scan asks of the remote and what it loads."""

    def submodule_repo(self):
        remote = Throwaway(self)
        remote.commit(
            "tree",
            "2025-01-10T12:00:00Z",
            {"CLAUDE.md": "Run `pnpm test`.\n", ".github/workflows/ci.yml": "steps:\n  - run: pnpm lint\n"},
        )
        # a .cursor/rules that is a submodule: its entry is a commit of another repo (mode 160000), not a blob
        remote.run("update-index", "--add", "--cacheinfo", "160000,%s,.cursor/rules" % SHA)
        remote.run("commit", "-q", "-m", "a submodule", date="2025-01-11T12:00:00Z")
        return remote

    def test_a_submodule_is_never_asked_for_as_a_blob(self):
        remote = self.submodule_repo()
        got = scan.read_tree(remote.path, remote.run("rev-parse", "HEAD").decode().strip())
        self.assertEqual(got["hits"]["cursor_rules"]["n"], 1)  # the path still counts
        self.assertNotIn(SHA, [oid for _, _, oid, _ in got["blobs"]])
        self.assertEqual(sorted(rule for rule, _, _, _ in got["blobs"]), ["claude_md", "workflows"])

    def test_a_repo_with_a_submodule_is_scanned(self):
        status, got, _ = scan_throwaway(self, self.submodule_repo())
        self.assertTrue(status.startswith("ok"), status)
        self.assertEqual(got["snaps"][-1]["checks"]["ci"], ["lint"])
        self.assertEqual(got["snaps"][-1]["checks"]["says"], ["tests"])

    def test_a_failed_fetch_is_said(self):
        remote = Throwaway(self)
        remote.commit("tree", "2025-01-10T12:00:00Z", {".github/workflows/ci.yml": "steps:\n  - run: pnpm lint\n"})
        status, got, _ = scan_throwaway(self, remote, fail_fetch=True)
        self.assertTrue(status.startswith("FAILED fetch of 1 blobs: fatal: remote error: refused"), status)
        self.assertIsNone(got)

    def test_a_file_over_the_limit_reads_as_one_not_fetched(self):
        self.assertEqual(scan.MAX_BLOB_BYTES, 1000000)
        big = "steps:\n  - run: pnpm test\n" + "#" * 200 + "\n"
        remote = Throwaway(self)
        remote.commit(
            "tree",
            "2025-01-10T12:00:00Z",
            {".github/workflows/big.yml": big, ".github/workflows/ci.yml": "steps:\n  - run: pnpm lint\n"},
        )
        with mock.patch.object(scan, "MAX_BLOB_BYTES", len(big) - 1):
            status, got, _ = scan_throwaway(self, remote)
        self.assertTrue(status.startswith("ok"), status)
        self.assertEqual(got["sets"][got["snaps"][-1]["set"]]["hits"]["workflows"]["n"], 2)  # both paths count
        self.assertEqual(got["snaps"][-1]["checks"]["ci"], ["lint"])  # the big one is not read


class Stored(unittest.TestCase):
    """The instruction files kept under data/raw/instructions."""

    def test_a_deep_file_and_two_names_that_differ_by_case_are_kept(self):
        deep = "/".join(["a" * 90, "b" * 90, "c" * 90]) + "/CLAUDE.md"
        self.assertGreater(len(deep.replace("/", "__")), 255)
        remote = Throwaway(self)
        remote.commit("base", "2025-01-09T12:00:00Z", {"README.md": "x"})
        # written with git's plumbing: this disk may ignore case, and the two files must both be in the commit
        for path, text in (
            (deep, "deep\n"),
            ("CLAUDE.md", "upper\n"),
            ("claude.md", "lower\n"),
            ("docs/CLAUDE.md", "docs\n"),
        ):
            oid = remote.run("hash-object", "-w", "--stdin", data=text.encode()).decode().strip()
            remote.run("update-index", "--add", "--cacheinfo", "100644,%s,%s" % (oid, path))
        remote.run("commit", "-q", "-m", "files", date="2025-01-10T12:00:00Z")
        status, got, out = scan_throwaway(self, remote)
        self.assertTrue(status.startswith("ok"), status)
        stored = {i["path"]: i["stored"] for i in got["instructions"]}
        self.assertEqual(set(stored), {deep, "CLAUDE.md", "claude.md", "docs/CLAUDE.md"})
        folder = out / "raw" / "instructions" / scan.slug(NAME)
        self.assertEqual(sorted(p.name for p in folder.iterdir()), sorted(stored.values()))
        for path, name in stored.items():
            with self.subTest(path=path):
                self.assertLessEqual(len(name.encode()), 255)
                self.assertEqual(name, name.lower())
                self.assertEqual(
                    (folder / name).read_text(),
                    {"CLAUDE.md": "upper\n", "claude.md": "lower\n", "docs/CLAUDE.md": "docs\n"}.get(path, "deep\n"),
                )


if __name__ == "__main__":
    unittest.main()
