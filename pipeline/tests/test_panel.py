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
ORGANISATION, ACTIVE_DAYS, MIN_FILES = "Organization", 90, 200
ROLL_MONTHS, WINDOW_DAYS, MIN_COMMITS, MIN_STARS, LADDER_SIZE = 18, 90, 30, 50, 200
ON = dt.date(2026, 11, 22)  # an invented day of build
AS_OF = dt.date(2026, 11, 17)  # an invented page date: its windows run from 2025-01-17 to 2025-05-17
DAYS = ["2025-01-17", "2025-02-17", "2025-03-17", "2025-04-17", "2025-05-17"]


def win(*counts, days=DAYS):
    """The windows of condition 5 with these counts, one a date."""
    return [{"day": d, "commits": n, "total": n, "cut": False} for d, n in zip(days, counts)]


def facts(**change):
    """A repo that passes every condition on ON for the page of AS_OF, with the facts given changed."""
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
        "windows": win(100, 100, 100, 100, 100),
    }
    f.update(change)
    return f


class Rule(unittest.TestCase):
    def test_a_repo_that_meets_every_condition_passes(self):
        self.assertEqual(panel.fails(facts(), ON, AS_OF), [])

    def test_files_at_the_edge(self):
        self.assertEqual(panel.fails(facts(files=199), ON, AS_OF), ["files"])
        self.assertEqual(panel.fails(facts(files=200), ON, AS_OF), [])
        self.assertEqual(panel.fails(facts(files=0), ON, AS_OF), ["files"])

    def test_one_window_at_30_is_enough_and_29_everywhere_is_not(self):
        self.assertEqual(panel.fails(facts(windows=win(29, 29, 29, 29, 29)), ON, AS_OF), ["already_active"])
        for i in range(5):
            counts = [29] * 5
            counts[i] = 30
            self.assertEqual(panel.fails(facts(windows=win(*counts)), ON, AS_OF), [], DAYS[i])
        # a repo whose history was rewritten since (prisma/orm answers no commit before June 2025 on its default branch)
        self.assertEqual(panel.fails(facts(windows=win(0, 0, 0, 0, 0)), ON, AS_OF), ["already_active"])
        # a floor (a count cut) at the threshold passes
        cut = [dict(w, cut=True) for w in win(30, 0, 0, 0, 0)]
        self.assertEqual(panel.fails(facts(windows=cut), ON, AS_OF), [])

    def test_a_window_after_the_start_does_not_count_and_one_before_the_first_neither(self):
        late = win(0, 0, 0, 0, 0) + win(500, days=["2025-06-17"])
        self.assertEqual(panel.fails(facts(windows=late), ON, AS_OF), ["already_active"])
        early = win(0, 0, 0, 0, 0) + win(500, days=["2024-12-17"])
        self.assertEqual(panel.fails(facts(windows=early), ON, AS_OF), ["already_active"])
        # the page of the next month counts 2025-06-17
        self.assertEqual(panel.fails(facts(windows=late), ON, dt.date(2026, 12, 17)), [])

    def test_the_creation_day_is_not_a_condition(self):
        """A repo created after the window's start can pass by commits older than the repo (a history brought in when it was
        created: charmbracelet/crush, created on 2025-05-21)."""
        self.assertEqual(panel.fails(facts(created="2025-05-21"), ON, AS_OF), [])
        self.assertEqual(panel.fails(facts(created=None), ON, AS_OF), [])

    def test_nobody_leaves_by_condition_5_at_the_next_issue(self):
        rng = random.Random(1)
        for _ in range(300):
            counts = [rng.choice([0, 10, 29, 30, 31, 80]) for _ in range(6)]
            days = DAYS + ["2025-06-17"]
            f = facts(windows=[{"day": d, "commits": n, "total": n, "cut": False} for d, n in zip(days, counts)])
            if not panel.fails(f, ON, AS_OF):
                self.assertEqual(panel.fails(f, ON, dt.date(2026, 12, 17)), [], counts)

    def test_the_90th_day_of_a_push(self):
        self.assertEqual(panel.fails(facts(pushed=(ON - dt.timedelta(days=90)).isoformat()), ON, AS_OF), [])
        self.assertEqual(panel.fails(facts(pushed=(ON - dt.timedelta(days=91)).isoformat()), ON, AS_OF), ["pushed"])
        self.assertEqual(panel.fails(facts(pushed=None), ON, AS_OF), ["pushed"])

    def test_a_person_a_fork_an_archived_or_private_repo(self):
        self.assertEqual(panel.fails(facts(owner_type="User"), ON, AS_OF), ["organisation"])
        self.assertEqual(panel.fails(facts(fork=True), ON, AS_OF), ["not_fork"])
        self.assertEqual(panel.fails(facts(archived=True), ON, AS_OF), ["not_archived"])
        self.assertEqual(panel.fails(facts(private=True), ON, AS_OF), ["public"])

    def test_a_vendors_owner_whatever_its_case(self):
        self.assertEqual(panel.fails(facts(name="openai/something", owner="openai"), ON, AS_OF), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="OpenAI/something", owner="OpenAI"), ON, AS_OF), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="oven-sh/bun", owner="oven-sh"), ON, AS_OF), ["not_vendor"])
        self.assertEqual(
            panel.fails(facts(name="charmbracelet/crush", owner="charmbracelet"), ON, AS_OF), ["not_vendor"]
        )

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
        self.assertEqual(panel.fails(dict(facts(), **moved), ON, AS_OF), ["not_vendor"])
        self.assertEqual(panel.fails(facts(name="openai/widget", owner="acme"), ON, AS_OF), [])
        self.assertEqual(panel.fails(facts(owner=None), ON, AS_OF), ["not_vendor"])  # an owner not read fails

    def test_a_fact_not_read_fails_and_every_failure_is_listed_in_order(self):
        self.assertEqual(panel.fails(facts(files=None, windows=None), ON, AS_OF), ["files", "already_active"])
        self.assertEqual(panel.fails(facts(windows=win(None, None)), ON, AS_OF), ["already_active"])
        self.assertEqual(panel.fails({"name": "acme/widget"}, ON, AS_OF), [c for c, _, _ in panel.CONDITIONS])
        self.assertEqual(
            panel.fails(facts(owner_type="User", fork=True, files=10, windows=win(3)), ON, AS_OF),
            ["organisation", "not_fork", "files", "already_active"],
        )

    def test_the_funnel_removes_a_repo_once_by_its_first_failure(self):
        out = panel.funnel([[], ["organisation", "files"], ["files"], ["already_active"], []], 5)
        removed = {s["condition"]: s["removed"] for s in out}
        self.assertEqual((removed["organisation"], removed["files"], removed["already_active"]), (1, 1, 1))
        self.assertEqual(out[-1]["left"], 2)
        self.assertEqual([s["condition"] for s in out], [c for c, _, _ in panel.CONDITIONS])

    def test_the_conditions_are_the_six_of_the_user_and_no_other(self):
        """Six conditions, numbered 1 to 6; the activity 18 months back or earlier is condition 5."""
        self.assertEqual(sorted({n for _, n, _ in panel.CONDITIONS}), [1, 2, 3, 4, 5, 6])
        self.assertEqual(len(panel.CONDITIONS), 8)  # condition 2 is three facts
        self.assertEqual(set(panel.CHEAP) | {"files", "already_active"}, {c for c, _, _ in panel.CONDITIONS})
        numbers = {c: n for c, n, _ in panel.CONDITIONS}
        self.assertEqual(
            numbers,
            {
                "organisation": 1,
                "public": 2,
                "not_archived": 2,
                "not_fork": 2,
                "pushed": 3,
                "files": 4,
                "already_active": 5,
                "not_vendor": 6,
            },
        )


class Windows(unittest.TestCase):
    def test_the_windows_run_from_the_grids_first_date_to_18_months_back(self):
        self.assertEqual([d.isoformat() for d in panel.windows(AS_OF)], DAYS)
        for as_of in (dt.date(2026, 11, 17), dt.date(2026, 12, 17), dt.date(2027, 3, 17), dt.date(2027, 1, 31)):
            got, grid = panel.windows(as_of), common.snapshot_dates(as_of)
            self.assertEqual(got[0], grid[0])
            self.assertEqual(got, grid[: len(grid) - ROLL_MONTHS])
            last = got[-1]
            self.assertEqual((as_of.year * 12 + as_of.month) - (last.year * 12 + last.month), ROLL_MONTHS)
        # one more date at each issue, none lost
        self.assertEqual(panel.windows(dt.date(2026, 12, 17))[:-1], panel.windows(dt.date(2026, 11, 17)))
        with self.assertRaises(ValueError):
            panel.windows(dt.date(2026, 6, 17))  # a grid with no date 18 months back

    def test_a_window_is_a_scans_commits90_behind_its_date(self):
        """The window of condition 5 at a date is the one scan.read_commits cuts behind that snapshot: the same length and the
        same edges (lo, hi], so that a test below can compare the two counts repo by repo. The scans' grid (common.AS_OF)
        holds every date of the rule's windows."""
        for d in panel.windows(common.AS_OF):
            lo, hi = panel.window_edges(d.isoformat())
            self.assertEqual(hi, common.end_of_day_ts(d))
            self.assertEqual(hi - lo, common.COMMIT_DAYS * 86400)
            self.assertIn(d, common.snapshot_dates(common.AS_OF))
        query = panel.history_query(["2025-01-17"], ON)
        self.assertIn('history(since:"2024-10-20T00:00:00Z", until:"2025-01-17T23:59:59Z", first:100)', query)
        self.assertIn('at: history(until:"2026-11-22T23:59:59Z", first:1)', query)  # the tip as of the day of the build

    def test_a_page_counts_the_commits_in_the_window_merges_left_out(self):
        nodes = [
            {"committedDate": "2024-10-19T23:59:59Z", "parents": {"totalCount": 1}},  # on the open edge: out
            {"committedDate": "2024-10-20T00:00:00Z", "parents": {"totalCount": 1}},
            {"committedDate": "2025-01-17T23:59:59Z", "parents": {"totalCount": 0}},  # a root commit counts
            {"committedDate": "2025-01-18T00:00:00Z", "parents": {"totalCount": 1}},  # past the date: out
            {"committedDate": "2025-01-10T00:00:00Z", "parents": {"totalCount": 2}},  # a merge: out
        ]
        self.assertEqual(panel.count_nodes("2025-01-17", {"nodes": nodes}), 2)

    def test_a_window_is_read_on_only_while_it_decides(self):
        """One query for every window's first page; a window under the threshold with more pages is read on, unless an
        earlier window reached it. A count stopped early is a floor (`cut`)."""
        node = {"committedDate": "2025-02-10T00:00:00Z", "parents": {"totalCount": 1}}
        merge = {"committedDate": "2025-02-10T00:00:00Z", "parents": {"totalCount": 2}}

        def page(nodes, more):
            return {"totalCount": 250, "pageInfo": {"hasNextPage": more, "endCursor": "c"}, "nodes": nodes}

        calls = []

        def fake(query, params=None, graphql=False, **_):
            calls.append(query)
            if "after:" in query:  # the second page of the window behind 2025-03-17: 40 commits
                w = {"w0": page([node] * 40, False)}
            else:  # 2025-02-17: 10 commits and 90 merges, more pages; 2025-03-17: the same; 2025-04-17: 100 commits
                w = {
                    "w0": page([node] * 10 + [merge] * 90, True),
                    "w1": page([node] * 100, True),
                    "w2": page([node] * 10 + [merge] * 90, True),
                }
            at = {
                "nodes": [{"oid": "t", "committedDate": "2026-11-20T10:00:00Z", "tree": {"oid": "x"}}]
            }  # the tip as of ON, not the tip of today ("now")
            return {
                "data": {"repository": {"defaultBranchRef": {"target": dict(w, oid="now", tree={"oid": "y"}, at=at)}}}
            }

        saved = panel.gh
        try:
            panel.gh = fake
            got, at, n = panel.read_windows("acme/widget", ["2025-02-17", "2025-03-17", "2025-04-17"], False, ON)
            self.assertEqual((at["oid"], at["tree"]["oid"], n, len(calls)), ("t", "x", 2, 2))
            self.assertEqual(got["2025-02-17"], {"commits": 50, "total": 250, "cut": False})  # read on: 10 + 40
            self.assertEqual(got["2025-03-17"], {"commits": 100, "total": 250, "cut": True})  # a floor, decided
            self.assertEqual(got["2025-04-17"], {"commits": 10, "total": 250, "cut": True})  # not read on: decided
            calls.clear()
            got, *_ = panel.read_windows("acme/widget", ["2025-02-17", "2025-03-17", "2025-04-17"], True, ON)
            self.assertEqual((len(calls), got["2025-02-17"]["commits"], got["2025-02-17"]["cut"]), (1, 10, True))
        finally:
            panel.gh = saved


class Thresholds(unittest.TestCase):
    def test_the_thresholds_are_the_ones_decided(self):
        self.assertEqual(
            (panel.OWNER_TYPE, common.ACTIVE_DAYS, panel.MIN_FILES), (ORGANISATION, ACTIVE_DAYS, MIN_FILES)
        )
        self.assertEqual(
            (panel.ROLL_MONTHS, panel.WINDOW_DAYS, panel.MIN_COMMITS, panel.MIN_STARS, panel.LADDER_SIZE),
            (ROLL_MONTHS, WINDOW_DAYS, MIN_COMMITS, MIN_STARS, LADDER_SIZE),
        )
        self.assertEqual(panel.WINDOW_DAYS, common.COMMIT_DAYS)
        for gone in ("CREATED_BEFORE", "EARLY_DAY", "EARLY_DAYS", "MIN_EARLY_COMMITS", "RULE"):
            self.assertFalse(hasattr(panel, gone), gone)

    def test_one_source(self):
        """`fails` and the files written read the constants: changing one changes the verdict, `rule` carries each, and
        panel.py types the numbers of the rule nowhere but on the lines that define them."""
        self.assertEqual(
            panel.rule(AS_OF),
            {
                "owner_type": panel.OWNER_TYPE,
                "active_days": common.ACTIVE_DAYS,
                "min_files": panel.MIN_FILES,
                "roll_months": panel.ROLL_MONTHS,
                "min_commits": panel.MIN_COMMITS,
                "commit_days": panel.WINDOW_DAYS,
                "first_day": DAYS[0],
                "window_start": DAYS[-1],
                "windows": DAYS,
                "min_stars": panel.MIN_STARS,
                "ladder_size": panel.LADDER_SIZE,
            },
        )
        saved = panel.MIN_FILES, panel.MIN_COMMITS, panel.ROLL_MONTHS
        try:
            panel.MIN_FILES, panel.MIN_COMMITS = 501, 101
            self.assertEqual(panel.fails(facts(), ON, AS_OF), ["files", "already_active"])
            panel.MIN_FILES, panel.MIN_COMMITS, panel.ROLL_MONTHS = saved[0], saved[1], 20
            self.assertEqual(panel.rule(AS_OF)["window_start"], "2025-03-17")
            self.assertEqual(panel.fails(facts(windows=win(0, 0, 0, 0, 100)), ON, AS_OF), ["already_active"])
        finally:
            panel.MIN_FILES, panel.MIN_COMMITS, panel.ROLL_MONTHS = saved
        source = (base.PIPELINE / "panel.py").read_text()
        code = [line.split("#")[0] for line in source.splitlines()]
        for pattern, defined in (
            (r"\b200\b", ["MIN_FILES = 200", "LADDER_SIZE = 200"]),
            (r"\b30\b", ["MIN_COMMITS = 30", "EARLY_PAGES = 30"]),
            (r"\b18\b(?! May)", ["ROLL_MONTHS = 18"]),  # a fact of LEFT_OUT is dated 18 May 2026
            (r"2025-\d\d-17|2025, \d+, 17", ['CACHED_EARLY_DAY = "2025-01-17"']),
            (r"2024-\d\d-\d\d|2024, \d", []),
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
        "charmbracelet",
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
        # the makers of a coding agent the page does not count, left out by name
        self.assertEqual(
            {o for o, e in panel.LEFT_OUT.items() if not e["tools"]},
            {"zed-industries", "openhands", "continuedev", "charmbracelet"},
        )


class Draw(unittest.TestCase):
    def test_the_days_order_reproduces_from_the_seed_and_covers_every_day(self):
        last = ON - dt.timedelta(days=1)
        days = panel.day_order(panel.RULE_SEED, panel.RULE_FIRST_DAY, last)
        self.assertEqual(days, panel.day_order(panel.RULE_SEED, panel.RULE_FIRST_DAY, last))
        self.assertEqual(len(set(days)), (last - panel.RULE_FIRST_DAY).days + 1)
        self.assertEqual((min(days), max(days)), (panel.RULE_FIRST_DAY, last))
        self.assertNotEqual(days, panel.day_order(panel.RULE_SEED + 1, panel.RULE_FIRST_DAY, last))

    def test_a_longer_span_keeps_the_order_of_the_days_it_had(self):
        short = panel.day_order(panel.RULE_SEED, panel.RULE_FIRST_DAY, ON)
        longer = panel.day_order(panel.RULE_SEED, panel.RULE_FIRST_DAY, ON + dt.timedelta(days=31))
        kept = set(short)
        self.assertEqual([d for d in longer if d in kept], short)


class Panels(unittest.TestCase):
    """The two panels, built under the rule."""

    PRO = base.panel("pro")
    LADDER = base.panel("ladder")
    INFO = base.read(base.DATA / "panel_rule.json")

    def test_every_candidate_passes_the_rule_on_its_facts_and_the_day_of_the_build(self):
        on, as_of = (dt.date.fromisoformat(self.INFO[k]) for k in ("built_on", "as_of"))
        days = self.INFO["rule"]["windows"]
        for e in self.PRO + self.LADDER:
            f = dict(e["facts"], name=e["name"])
            self.assertEqual(panel.fails(f, on, as_of), [], e["name"])
            self.assertEqual((f["created"], f["pushed"]), (e["created_at"], e["pushed_at"]), e["name"])
            self.assertEqual(e["name"].split("/")[0], f["owner"], e["name"])
            self.assertEqual([w["day"] for w in f["windows"]], days, e["name"])
            active = [w["day"] for w in f["windows"] if w["commits"] >= panel.MIN_COMMITS]
            self.assertEqual(f["active_on"], active[0], e["name"])
            self.assertEqual(f["best"], max(w["commits"] for w in f["windows"]), e["name"])
            self.assertTrue(all(w["commits"] <= w["total"] for w in f["windows"]), e["name"])
        self.assertTrue(all(e["stars"] >= panel.MIN_STARS for e in self.LADDER))

    def test_the_files_say_the_rule_they_were_built_by(self):
        self.assertEqual(self.INFO["rule"], panel.rule(dt.date.fromisoformat(self.INFO["as_of"])))
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
        on = dt.date.fromisoformat(self.INFO["built_on"])
        self.assertEqual(
            (lad["first_day"], lad["last_day"]),
            (panel.RULE_FIRST_DAY.isoformat(), (on - dt.timedelta(days=1)).isoformat()),
        )
        days = panel.day_order(lad["seed"], panel.RULE_FIRST_DAY, on - dt.timedelta(days=1))
        self.assertEqual(lad["span_days"], len(days))
        self.assertEqual(lad["order"], panel.ORDER)
        self.assertEqual([s["day"] for s in lad["steps"]], [d.isoformat() for d in days[: lad["days_taken"]]])
        self.assertEqual(lad["pool"], len(lad["pool_names"]))
        self.assertEqual(lad["steps"][-1]["pool"], lad["pool"])
        self.assertGreaterEqual(lad["pool"], panel.LADDER_SIZE)
        self.assertLess(lad["steps"][-2]["pool"], panel.LADDER_SIZE)  # the draw stops at the first day that reaches it
        drawn = random.Random(lad["seed"]).sample(lad["pool_names"], panel.LADDER_SIZE)
        self.assertEqual(sorted(drawn, key=str.lower), [e["name"] for e in self.LADDER])
        self.assertEqual(lad["funnel"][-1]["left"], lad["pool"])
        pro = {e["name"].lower() for e in self.PRO}
        self.assertFalse(pro & {n.lower() for n in lad["pool_names"]})

    def test_the_build_of_2026_11_22_under_the_rolling_rule(self):
        """The build of 2026-11-22 for the page of 2026-11-17, from that day's cache and the windows read on 2026-11-27: the
        209 of the fixed rule stay, 13 enter (one only by condition 3 gone, simstudioai/sim, created 2025-01-05), and
        charmbracelet/crush, which would enter, is left out with its owner, named on 2026-11-27. The ladder loses 10 drawn
        repos to the owners whose profile names Microsoft or Google, read on 2026-11-27, and is drawn again."""
        self.assertEqual((self.INFO["built_on"], self.INFO["as_of"]), ("2026-11-22", "2026-11-17"))
        self.assertEqual((len(self.PRO), self.INFO["pro"]["repos"]), (222, 427))
        lad = self.INFO["ladder"]
        self.assertEqual((len(self.LADDER), lad["pool"], lad["days_taken"], lad["considered"]), (200, 204, 68, 2012))
        self.assertEqual({s["read_on"] for s in lad["steps"]}, {"2026-11-27"})  # every day searched on 2026-11-27
        names = {e["name"].lower() for e in self.PRO} | {n.lower() for n in self.INFO["ladder"]["pool_names"]}
        for gone in (
            "openhands/openhands",
            "continuedev/continue",
            "dotnet/dotnext",
            "dotnet/nerdbank.gitversioning",
            "charmbracelet/crush",
        ):
            self.assertNotIn(gone, names)
        entered = {
            "AsyncFuncAI/deepwiki-open",
            "ComposioHQ/composio",
            "Mail-0/Zero",
            "ag-ui-protocol/ag-ui",
            "atuinsh/atuin",
            "dyad-sh/dyad",
            "freshframework/fresh",
            "nanobrowser/nanobrowser",
            "radix-ui/primitives",
            "simstudioai/sim",
            "stagewise-io/stagewise",
            "supermemoryai/supermemory",
            "upstash/context7",
        }
        self.assertLessEqual(entered, {e["name"] for e in self.PRO})
        active_on = {}
        for e in self.PRO:
            active_on[e["facts"]["active_on"]] = active_on.get(e["facts"]["active_on"], 0) + 1
        self.assertEqual(
            active_on, {"2025-01-17": 210, "2025-02-17": 3, "2025-03-17": 2, "2025-04-17": 2, "2025-05-17": 5}
        )


def scans_and_rule():
    """For every repo of both panels: the rule's facts (the day of the build) beside its scan (made with the run date of
    2026-11-17, so its last snapshot is the default branch on that date and its snapshots at the rule's dates count the
    commits of the rule's windows). A date the repo had no commit by is a snapshot the scan holds as null, and its count is
    0: under the rolling rule a repo can enter with no commit at the grid's first dates."""
    out = []
    for e in Panels.PRO + Panels.LADDER:
        scan = base.scan(e["name"])
        out.append((e, {s["date"]: s for s in scan["snaps"] if s}, scan["snaps"][-1]))
    return out


def commits(snaps, day):
    """A scan's `commits90` at a date: 0 where the repo had no commit by then (no snapshot)."""
    return snaps[day]["commits90"]["total"] if day in snaps else 0


@base.needs(base.DATA / "scan")
@base.needs(base.DATA / "meta.json")
class Scans(unittest.TestCase):
    """The scans against the rule's facts, repo by repo. Two counts are read twice, by the API on the day of the build and
    by the scan's clone, and may differ only by a cause known and checked here:
    - the files at the tip: the same commit gives the same count (a tree GitHub cut gives a floor, which the scan can only
      pass); a different commit is the default branch moved between the scan's last snapshot (the run date) and the build,
      which a push after the run date shows;
    - the commits of each window: a scan can count fewer (GitHub's shallow clone drops the commits of the window that
      sit behind an older-dated commit: seen on python-discord/bot on 2026-11-22), and a few more, never more than the
      window's merges (a merge whose parents are behind the shallow cut is read by the clone as a commit with fewer
      parents, so the scan does not leave it out as a merge: shown on coroot/coroot, 45 against 44, through the API on
      2026-11-22); GitHub's total of the window, merges included, bounds both. A count of the rule's cut is a floor of the rule's
      count only: the scan can count fewer still (OnePlusOSS/android_kernel_common_oneplus_sm8750: 0 against 100, 2026-11-27)."""

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
                else:  # the branch moved after the run date: a push read on the day of the build, or the tip that day
                    # dated after the run date (pushed later that day than GitHub was read: AsyncFuncAI/deepwiki-open)
                    self.assertTrue(f["pushed"] > self.AS_OF or (f["tip_date"] or "") > self.AS_OF)

    def test_the_commits_of_each_window(self):
        for e, snaps, _ in self.ROWS:
            for w in e["facts"]["windows"]:
                with self.subTest(repo=e["name"], day=w["day"]):
                    got = commits(snaps, w["day"])
                    if w["day"] not in snaps and w["commits"]:  # a state the scan cannot give (first parents)
                        self.assertIn(e["name"], NO_STATE)
                    else:  # a count cut is a floor of the rule's, not of the scan's, which the shallow clone can lower
                        self.assertLessEqual(got, w["total"])

    def test_the_window_that_lets_a_repo_in_is_in_its_scan_too(self):
        """The scan's count at the date the repo reached the threshold, against the rule's: the repos where the two sides of
        the threshold differ are the ones named here (a finding, not a test to loosen)."""
        below = sorted(e["name"] for e, snaps, _ in self.ROWS if commits(snaps, e["facts"]["active_on"]) < MIN_COMMITS)
        self.assertEqual(below, BELOW_IN_SCAN)

    def test_every_repo_has_a_state_at_the_windows_start_but_the_ones_named(self):
        """The rule says a repo was active by the window's start, so its scan has a state there: but for a repo whose first
        parents begin later than the commits the rule counts (NO_STATE)."""
        start = Panels.INFO["rule"]["window_start"]
        self.assertEqual(sorted(e["name"] for e, snaps, _ in self.ROWS if start not in snaps), NO_STATE)

    def test_how_many_of_each(self):
        """The distribution as found on 2026-11-27: a change is a finding to read, not a test to loosen."""
        same_tip = sum(1 for e, _, last in self.ROWS if last["sha"] == e["facts"]["tip"])
        first = [
            commits(snaps, e["facts"]["windows"][0]["day"]) - e["facts"]["windows"][0]["commits"]
            for e, snaps, _ in self.ROWS
            if not e["facts"]["windows"][0]["cut"]
        ]
        self.assertEqual((len(self.ROWS), same_tip), HOW_MANY["rows_same_tip"])
        self.assertEqual(
            (sum(1 for d in first if d == 0), sum(1 for d in first if d < 0), sum(1 for d in first if d > 0)),
            HOW_MANY["first_window"],
        )
        cut = sum(1 for e, _, _ in self.ROWS for w in e["facts"]["windows"] if w["cut"])
        self.assertEqual(cut, HOW_MANY["cut_windows"])


# Found on 2026-11-27 in the scans of both panels. Under 30 in the scan at the date the rule's count reached 30: six by the
# shallow clone (a scan can count fewer), and jumpstarter-dev/jumpstarter, put together on 2026-01-22 by merging older
# repositories: the rule counts every ancestor (60 to 76 commits in each window of 2025), the scan picks a snapshot along
# first parents, which begin in 2026, so it holds no state before 2026-02-17, not even at the window's start.
BELOW_IN_SCAN = [
    "OnePlusOSS/android_kernel_common_oneplus_sm8750",
    "UoB-HPC/BabelStream",
    "Z-Hub/Z-Push",
    "antigenomics/vdjdb-db",
    "atheme/atheme",
    "jumpstarter-dev/jumpstarter",
    "zendesk/maxwell",
]
NO_STATE = ["jumpstarter-dev/jumpstarter"]  # the repos with commits in a window and no state at its date in the scan
HOW_MANY = {"rows_same_tip": (422, 123), "first_window": (250, 45, 42), "cut_windows": 1118}


if __name__ == "__main__":
    unittest.main()
