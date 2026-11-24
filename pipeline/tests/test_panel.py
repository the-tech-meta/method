"""The rule both leagues are built by (panel.py), the ROSS list it reads, and the owners it leaves out.

The rule's function is tried on invented facts at each edge. Its thresholds are retyped here, so a threshold changed in
the code alone fails a test, and the code is held to read them from one place. The tests of the built panels read the
panel files; those that compare them with the scans (data/scan) are skipped when the scans are not there.
"""

import datetime as dt
import random
import re
import unittest

import base
import analyze
import common
import panel

# The rule's thresholds, typed again
ORGANISATION, CREATED_BEFORE, ACTIVE_DAYS, MIN_FILES = "Organization", dt.date(2025, 1, 1), 90, 200
EARLY_DAY, EARLY_DAYS, MIN_EARLY_COMMITS, MIN_STARS, LADDER_SIZE = dt.date(2025, 1, 17), 90, 30, 50, 200
ON = dt.date(2026, 11, 22)  # an invented day of build


def facts(**change):
    """A repo that passes every condition on ON, with the facts given changed."""
    f = {
        "name": "acme/widget",
        "owner": "acme",
        "owner_type": "Organization",
        "private": False,
        "archived": False,
        "fork": False,
        "created": "2020-05-01",
        "pushed": (ON - dt.timedelta(days=10)).isoformat(),
        "files": 500,
        "early_commits": 100,
    }
    f.update(change)
    return f


class Rule(unittest.TestCase):
    def test_a_repo_that_meets_every_condition_passes(self):
        self.assertEqual(panel.fails(facts(), ON), [])

    def test_files_at_the_edge(self):
        self.assertEqual(panel.fails(facts(files=199), ON), ["files"])
        self.assertEqual(panel.fails(facts(files=200), ON), [])
        self.assertEqual(panel.fails(facts(files=0), ON), ["files"])

    def test_early_commits_at_the_edge(self):
        self.assertEqual(panel.fails(facts(early_commits=29), ON), ["early_commits"])
        self.assertEqual(panel.fails(facts(early_commits=30), ON), [])
        # a repo whose history was rewritten since (prisma/orm answers no commit before June 2025 on its default
        # branch) fails
        self.assertEqual(panel.fails(facts(early_commits=0), ON), ["early_commits"])

    def test_the_two_creation_dates(self):
        self.assertEqual(panel.fails(facts(created="2024-12-31"), ON), [])
        self.assertEqual(panel.fails(facts(created="2025-01-01"), ON), ["created"])

    def test_the_90th_day_of_a_push(self):
        self.assertEqual(panel.fails(facts(pushed=(ON - dt.timedelta(days=90)).isoformat()), ON), [])
        self.assertEqual(panel.fails(facts(pushed=(ON - dt.timedelta(days=91)).isoformat()), ON), ["pushed"])
        self.assertEqual(panel.fails(facts(pushed=None), ON), ["pushed"])

    def test_a_person_a_fork_an_archived_or_private_repo(self):
        self.assertEqual(panel.fails(facts(owner_type="User"), ON), ["organisation"])
        self.assertEqual(panel.fails(facts(fork=True), ON), ["not_fork"])
        self.assertEqual(panel.fails(facts(archived=True), ON), ["not_archived"])
        self.assertEqual(panel.fails(facts(private=True), ON), ["public"])

    def test_a_vendors_owner_whatever_its_case(self):
        self.assertEqual(panel.fails(facts(name="openai/something", owner="openai"), ON), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="OpenAI/something", owner="OpenAI"), ON), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="oven-sh/bun", owner="oven-sh"), ON), ["not_vendor"])

    def test_the_owner_is_the_one_github_answers_not_the_name_typed(self):
        """A repo moved under a vendor's organisation is left out, whatever name a list types for it; and one moved out of a
        vendor's organisation is not. `repo_facts` takes the owner from GitHub's answer."""
        answer = {
            "full_name": "openai/widget",
            "owner": {"login": "openai", "type": "Organization"},
            "private": False,
            "archived": False,
            "fork": False,
            "created_at": "2020-05-01T00:00:00Z",
            "pushed_at": facts()["pushed"] + "T00:00:00Z",
            "stargazers_count": 60,
            "default_branch": "main",
            "size": 1000,
            "language": "Go",
        }
        moved = panel.repo_facts(answer)  # the call was made as "acme/widget"; GitHub followed the move
        self.assertEqual((moved["name"], moved["owner"]), ("openai/widget", "openai"))
        self.assertEqual(panel.fails(dict(facts(), **moved), ON), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="openai/widget", owner="acme"), ON), [])
        self.assertEqual(panel.fails(facts(owner=None), ON), ["not_vendor"])  # an owner not read fails

    def test_a_fact_not_read_fails_and_every_failure_is_listed_in_order(self):
        self.assertEqual(panel.fails(facts(files=None, early_commits=None), ON), ["files", "early_commits"])
        self.assertEqual(panel.fails({"name": "acme/widget"}, ON), [c for c, _, _ in panel.CONDITIONS])
        self.assertEqual(
            panel.fails(facts(owner_type="User", fork=True, created="2025-02-01", files=10), ON),
            ["organisation", "not_fork", "created", "files"],
        )

    def test_the_funnel_removes_a_repo_once_by_its_first_failure(self):
        out = panel.funnel([[], ["organisation", "files"], ["files"], ["early_commits"], []], 5)
        removed = {s["condition"]: s["removed"] for s in out}
        self.assertEqual((removed["organisation"], removed["files"], removed["early_commits"]), (1, 1, 1))
        self.assertEqual(out[-1]["left"], 2)

    def test_the_conditions_are_the_seven_of_the_user_and_no_other(self):
        self.assertEqual(sorted({n for _, n, _ in panel.CONDITIONS}), [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(len(panel.CONDITIONS), 9)  # condition 2 is three facts
        self.assertEqual(set(panel.CHEAP) | {"files", "early_commits"}, {c for c, _, _ in panel.CONDITIONS})


class Thresholds(unittest.TestCase):
    def test_the_thresholds_are_the_ones_decided(self):
        self.assertEqual(
            (panel.OWNER_TYPE, panel.CREATED_BEFORE, common.ACTIVE_DAYS, panel.MIN_FILES),
            (ORGANISATION, CREATED_BEFORE, ACTIVE_DAYS, MIN_FILES),
        )
        self.assertEqual(
            (panel.EARLY_DAY, panel.EARLY_DAYS, panel.MIN_EARLY_COMMITS, panel.MIN_STARS, panel.LADDER_SIZE),
            (EARLY_DAY, EARLY_DAYS, MIN_EARLY_COMMITS, MIN_STARS, LADDER_SIZE),
        )

    def test_the_early_window_is_a_scans_commits90_at_the_first_snapshot(self):
        """The window of condition 6 is the one scan.read_commits cuts behind the first snapshot: the same day, the same length,
        the same edges (lo, hi], so that a later test can compare the two counts repo by repo."""
        first = common.snapshot_dates(common.AS_OF)[0]
        self.assertEqual(panel.EARLY_DAY, first)
        self.assertEqual(panel.EARLY_DAYS, common.COMMIT_DAYS)
        self.assertEqual(panel.EARLY_HI, common.end_of_day_ts(first))
        self.assertEqual(panel.EARLY_HI - panel.EARLY_LO, common.COMMIT_DAYS * 86400)

    def test_one_source(self):
        """`fails` and the files written read the constants: changing one changes the verdict, RULE carries each, and panel.py types
        the numbers of the rule nowhere but on the lines that define them."""
        self.assertEqual(
            panel.RULE,
            {
                "owner_type": panel.OWNER_TYPE,
                "created_before": panel.CREATED_BEFORE.isoformat(),
                "active_days": common.ACTIVE_DAYS,
                "min_files": panel.MIN_FILES,
                "early_day": panel.EARLY_DAY.isoformat(),
                "early_days": panel.EARLY_DAYS,
                "min_early_commits": panel.MIN_EARLY_COMMITS,
                "min_stars": panel.MIN_STARS,
                "ladder_size": panel.LADDER_SIZE,
            },
        )
        saved = panel.MIN_FILES, panel.MIN_EARLY_COMMITS, panel.CREATED_BEFORE
        try:
            panel.MIN_FILES, panel.MIN_EARLY_COMMITS, panel.CREATED_BEFORE = 501, 101, dt.date(2020, 5, 1)
            self.assertEqual(panel.fails(facts(), ON), ["created", "files", "early_commits"])
        finally:
            panel.MIN_FILES, panel.MIN_EARLY_COMMITS, panel.CREATED_BEFORE = saved
        source = (base.PIPELINE / "panel.py").read_text()
        code = [line.split("#")[0] for line in source.splitlines()]
        for pattern, defined in (
            (r"\b200\b", ["MIN_FILES = 200", "LADDER_SIZE = 200"]),
            (r"\b30\b", ["MIN_EARLY_COMMITS = 30", "EARLY_PAGES = 30"]),
            (r"2025, 1, 1\b|2025-01-01", ["CREATED_BEFORE = dt.date(2025, 1, 1)"]),
            (r"2025, 1, 17|2025-01-17", ["EARLY_DAY = dt.date(2025, 1, 17)"]),
        ):
            lines = [line.strip() for line in code if re.search(pattern, line)]
            self.assertEqual(lines, defined, pattern)
        self.assertNotRegex(source, r"(?m)^[^#\n]*\b90\b")  # ACTIVE_DAYS and COMMIT_DAYS come from common.py


class Ross(unittest.TestCase):
    ROSS = base.read(base.DATA / "ross_index.json")

    def test_the_list_says_its_source_and_the_day_it_was_read(self):
        self.assertEqual(self.ROSS["url"], "https://runacap.com/ross-index/")
        self.assertRegex(self.ROSS["read_on"], r"^\d{4}-\d\d-\d\d$")
        for key in ("source", "methodology", "kept", "left_out", "add_an_edition"):
            self.assertTrue(self.ROSS[key], key)

    def test_each_edition_is_a_page_and_the_repos_it_links_with_no_rank(self):
        ids = [e["id"] for e in self.ROSS["editions"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[0], "q2-2020")
        for e in self.ROSS["editions"]:
            self.assertEqual(set(e), {"id", "url", "repos"}, e["id"])  # no rank, no figure
            self.assertRegex(e["id"], r"^(q[1-4]|annual)-20\d\d$")
            self.assertEqual(e["url"], "https://runacap.com/ross-index/%s/" % e["id"])
            self.assertEqual(
                e["repos"], sorted(set(e["repos"]), key=str.lower), e["id"]
            )  # sorted: the page's order is its rank
            self.assertTrue(all(re.match(r"^[\w.-]+/[\w.-]+$", r) for r in e["repos"]), e["id"])


class Vendors(unittest.TestCase):
    NAMED = {
        "anthropics",
        "openai",
        "cursor",
        "getcursor",
        "github",
        "microsoft",
        "google",
        "google-gemini",
        "sourcegraph",
        "zed-industries",
        "cline",
        "oven-sh",
        "astral-sh",
        "openhands",
        "continuedev",
        "dotnet",
    }  # the owners left out by name (the "named" ties of panel.LEFT_OUT)

    def test_every_tool_the_page_counts_has_an_owner_left_out(self):
        tools = {key for key, *_ in analyze.TOOLS}
        covered = {t for e in panel.LEFT_OUT.values() if e["tie"] in ("maker", "bought") for t in e["tools"]}
        self.assertEqual(tools - covered, set())
        self.assertTrue(all(set(e["tools"]) <= tools for e in panel.LEFT_OUT.values()))

    def test_every_owner_is_lowercase_with_a_fact_and_a_link(self):
        for owner, e in panel.LEFT_OUT.items():
            self.assertEqual(owner, owner.lower())
            self.assertIn(e["tie"], ("maker", "bought", "named"), owner)
            self.assertTrue(e["fact"], owner)
            self.assertRegex(e["link"], r"^https://[\w.-]+\.[a-z]+(/|$)", owner)
        self.assertLessEqual(self.NAMED, set(panel.LEFT_OUT))

    def test_the_ladder_draw_reproduces_from_its_seed(self):
        """The ladder's days come from the seed alone: `build_rule_ladder` draws them as below."""
        span = (panel.CREATED_BEFORE - panel.RULE_FIRST_DAY).days
        rng = random.Random(panel.RULE_SEED)
        days = [panel.RULE_FIRST_DAY + dt.timedelta(days=d) for d in rng.sample(range(span), span)]
        self.assertEqual(len(set(days)), span)
        self.assertTrue(all(panel.RULE_FIRST_DAY <= d < panel.CREATED_BEFORE for d in days))


class Panels(unittest.TestCase):
    """The two panels, built under the rule."""

    PRO = base.panel("pro")
    LADDER = base.panel("ladder")
    INFO = base.read(base.DATA / "panel_rule.json")

    def test_every_candidate_passes_the_rule_on_its_facts_and_the_day_of_the_build(self):
        on = dt.date.fromisoformat(self.INFO["built_on"])
        for e in self.PRO + self.LADDER:
            f = dict(e["facts"], name=e["name"])
            self.assertEqual(panel.fails(f, on), [], e["name"])
            self.assertEqual((f["created"], f["pushed"]), (e["created_at"], e["pushed_at"]), e["name"])
            self.assertEqual(e["name"].split("/")[0], f["owner"], e["name"])
        self.assertTrue(all(e["stars"] >= panel.MIN_STARS for e in self.LADDER))

    def test_the_files_say_the_rule_they_were_built_by(self):
        self.assertEqual(self.INFO["rule"], panel.RULE)
        self.assertEqual(self.INFO["conditions"], [list(c) for c in panel.CONDITIONS])
        self.assertEqual(self.INFO["left_out"], sorted(panel.LEFT_OUT))

    def test_an_entry_is_a_panel_entry_scan_py_reads(self):
        """Every key of a panel entry that scan.py and api_signals.py read. An entry has no kind."""
        keys = {
            "name",
            "league",
            "category",
            "stars",
            "created_at",
            "pushed_at",
            "default_branch",
            "size_kb",
            "language",
        }
        for e in self.PRO + self.LADDER:
            self.assertLessEqual(keys, set(e), e["name"])
            self.assertIsNone(e["category"], e["name"])
        self.assertEqual({e["league"] for e in self.PRO}, {"pro"})
        self.assertEqual({e["league"] for e in self.LADDER}, {"ladder"})

    def test_no_owner_is_a_person_or_a_vendor_and_the_leagues_do_not_meet(self):
        for e in self.PRO + self.LADDER:
            self.assertEqual(e["facts"]["owner_type"], "Organization", e["name"])
            self.assertNotIn(e["name"].split("/")[0].lower(), panel.LEFT_OUT, e["name"])
        names = [e["name"].lower() for e in self.PRO + self.LADDER]
        self.assertEqual(len(names), len(set(names)))

    def test_the_pro_scene_is_the_ross_repos_that_pass(self):
        editions = [e["id"] for e in base.read(base.DATA / "ross_index.json")["editions"]]
        for e in self.PRO:
            self.assertTrue(e["ross"], e["name"])
            self.assertEqual(e["ross"], sorted(set(e["ross"]), key=editions.index), e["name"])
        pro = self.INFO["pro"]
        self.assertEqual(pro["passed"], len(self.PRO))
        self.assertEqual(pro["funnel"][-1]["left"], len(self.PRO))
        self.assertEqual(sum(s["removed"] for s in pro["funnel"]) + len(self.PRO), pro["repos"])

    def test_the_ladder_is_drawn_again_from_its_seed_and_its_pool(self):
        lad = self.INFO["ladder"]
        span = (panel.CREATED_BEFORE - panel.RULE_FIRST_DAY).days
        rng = random.Random(lad["seed"])
        days = [panel.RULE_FIRST_DAY + dt.timedelta(days=d) for d in rng.sample(range(span), span)]
        self.assertEqual([s["day"] for s in lad["steps"]], [d.isoformat() for d in days[: lad["days_taken"]]])
        self.assertEqual(lad["pool"], len(lad["pool_names"]))
        self.assertEqual(lad["steps"][-1]["pool"], lad["pool"])
        self.assertGreaterEqual(lad["pool"], panel.LADDER_SIZE)
        self.assertLess(lad["steps"][-2]["pool"], panel.LADDER_SIZE)  # the draw stops at the first day that reaches it
        drawn = rng.sample(lad["pool_names"], panel.LADDER_SIZE)
        self.assertEqual(sorted(drawn, key=str.lower), [e["name"] for e in self.LADDER])
        self.assertEqual(lad["funnel"][-1]["left"], lad["pool"])
        pro = {e["name"].lower() for e in self.PRO}
        self.assertFalse(pro & {n.lower() for n in lad["pool_names"]})

    def test_the_build_of_2026_11_22_and_the_owners_named_that_day(self):
        """The build of 2026-11-22, from that day's cache: three owners are left out (openhands,
        continuedev, dotnet). The pro scene is the 211 of a build without that rule less OpenHands/OpenHands and
        continuedev/continue, the ladder 200 drawn from a pool of 203 (205 less dotnet's two repos), over the same 70
        days."""
        self.assertEqual(self.INFO["built_on"], "2026-11-22")
        self.assertEqual((len(self.PRO), self.INFO["pro"]["repos"]), (209, 427))
        self.assertEqual(
            (len(self.LADDER), self.INFO["ladder"]["pool"], self.INFO["ladder"]["days_taken"]), (200, 203, 70)
        )
        names = {e["name"].lower() for e in self.PRO} | {n.lower() for n in self.INFO["ladder"]["pool_names"]}
        for gone in ("openhands/openhands", "continuedev/continue", "dotnet/dotnext", "dotnet/nerdbank.gitversioning"):
            self.assertNotIn(gone, names)


def scans_and_rule():
    """For every repo of both panels: the rule's facts (the day of the build) beside its scan (made with the run date of
    2026-11-17, so its last snapshot is the default branch on that date and its first counts the commits of the rule's
    window)."""
    out = []
    for e in Panels.PRO + Panels.LADDER:
        scan = base.scan(e["name"])
        out.append((e, scan["snaps"][0], scan["snaps"][-1]))
    return out


@base.needs(base.DATA / "scan")
@base.needs(base.DATA / "meta.json")
class Scans(unittest.TestCase):
    """The scans against the rule's facts, repo by repo. Two counts are read twice, by the API on the day of the build and
    by the scan's clone, and may differ only by a cause known and checked here:
    - the files at the tip: the same commit gives the same count (a tree GitHub cut gives a floor, which the scan can only
      pass); a different commit is the default branch moved between the scan's last snapshot (the run date) and the build,
      which a push after the run date shows;
    - the commits of the early window: a scan can count fewer (GitHub's shallow clone drops the commits of the window that
      sit behind an older-dated commit: seen on python-discord/bot on 2026-11-22), and a few more, never more than the
      window's merges (a merge whose parents are behind the shallow cut is read by the clone as a commit with fewer
      parents, so the scan does not leave it out as a merge: shown on coroot/coroot, 45 against 44, through the API on
      2026-11-22); a count of the rule's past its pages (early_cut) is a floor, which the scan can only pass."""

    @classmethod
    def setUpClass(cls):
        cls.ROWS = scans_and_rule()
        cls.AS_OF = base.meta()["as_of"]

    def test_the_files_at_the_tip(self):
        for e, _, last in self.ROWS:
            f = e["facts"]
            with self.subTest(repo=e["name"]):
                if last["sha"] == f["tip"]:
                    if f["files_cut"]:
                        self.assertGreaterEqual(last["files"], f["files"])
                    else:
                        self.assertEqual(last["files"], f["files"])
                else:
                    self.assertGreater(f["pushed"], self.AS_OF)  # the branch moved after the run date

    def test_the_commits_of_the_early_window(self):
        for e, first, _ in self.ROWS:
            f = e["facts"]
            got = first["commits90"]["total"]
            with self.subTest(repo=e["name"]):
                self.assertEqual(first["date"], panel.EARLY_DAY.isoformat())
                if f["early_cut"]:
                    self.assertGreaterEqual(got, f["early_commits"])
                else:
                    self.assertLessEqual(got - f["early_commits"], f["early_total"] - f["early_commits"])

    def test_how_many_of_each(self):
        """The distribution as found on 2026-11-22: a change is a finding to read, not a test to loosen."""
        same_tip = sum(1 for e, _, last in self.ROWS if last["sha"] == e["facts"]["tip"])
        diff = [first["commits90"]["total"] - e["facts"]["early_commits"] for e, first, _ in self.ROWS]
        self.assertEqual((len(self.ROWS), same_tip), (409, 117))
        self.assertEqual(
            (sum(1 for d in diff if d == 0), sum(1 for d in diff if d < 0), sum(1 for d in diff if d > 0)),
            (286, 59, 64),
        )
        self.assertEqual(sum(1 for e, _, _ in self.ROWS if e["facts"]["early_cut"]), 4)


if __name__ == "__main__":
    unittest.main()
