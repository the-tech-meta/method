"""The pure functions of analyze.py on small inputs worked out by hand."""

import datetime as dt
import unittest

import base  # noqa: F401  (sets the run date before analyze is imported)
import analyze as A

# One practice, "x", over six snapshots for six invented repos. None: the repo has no state yet, it did not exist.
# The panel is fixed: at a snapshot where a repo has no state, it counts as not having the practice.
T, F = True, False
X = {
    "a": [F, T, T, T, T, T],  # had it BACK snapshots ago and still has it
    "b": [T, T, F, F, F, F],  # had it early, gone by snapshot 2
    "c": [None, None, None, F, T, T],  # created after "then" (snapshot 2): without it then, so it added it
    "d": [F, F, T, T, T, F],  # lost it in the last three months, gone by snapshot 5
    "e": [F, F, F, F, F, T],  # gained it in the last three months
    "f": [T, T, T, T, T, F],  # lost it too, gone by snapshot 5
}


def repos(feature="x", extra=None):
    out = []
    for name, xs in X.items():
        f = [None if x is None else dict(extra or {}, **{feature: x}) for x in xs]
        out.append({"name": name, "f": f, "now": f[-1]})
    return out


class Numbers(unittest.TestCase):
    def test_wilson(self):
        self.assertEqual(A.wilson(0, 0), (0.0, 0.0))
        lo, hi = A.wilson(0, 10)
        self.assertEqual((lo, round(hi, 4)), (0.0, 0.2775))
        lo, hi = A.wilson(5, 10)
        self.assertEqual((round(lo, 4), round(hi, 4)), (0.2366, 0.7634))
        lo, hi = A.wilson(10, 10)
        self.assertEqual((round(lo, 4), hi), (0.7225, 1.0))

    def test_share(self):
        self.assertEqual(A.share(1, 3), {"k": 1, "n": 3, "p": 0.3333, "lo": 0.0615, "hi": 0.7923})
        self.assertEqual(A.share(0, 0), {"k": 0, "n": 0, "p": 0, "lo": 0.0, "hi": 0.0})
        self.assertEqual(A.share(2, 3)["p"], 0.6667)

    def test_a_sentence_gives_no_percentage_under_the_floor(self):
        # the floor of a percentage: 20 repos. At it a share is a percentage; under it, a sentence must say the count
        self.assertEqual(A.MIN_BASE, 20)
        self.assertEqual(A.pc(A.share(5, 20)), "25%")
        self.assertEqual(A.pc({"p": 0.6327}), "63%", "a point of a series, over its league")
        with self.assertRaises(ValueError):
            A.pc(A.share(2, 4))
        with self.assertRaises(ValueError):
            A.pc(A.share(19, 19))

    def test_pro_lead(self):
        share = lambda k, n: {"k": k, "n": n}
        # from the counts, not from rounded shares: 31 of 98 against 1 of 230 would be 72.8, and is not shown
        # (1 ladder repo)
        self.assertIsNone(A.lead(share(31, 98), share(1, 230)))
        self.assertIsNone(A.lead(share(9, 98), share(40, 230)), "9 pro repos: under 10")
        self.assertIsNone(A.lead(share(62, 98), share(9, 230)), "9 ladder repos: under 10")
        self.assertEqual(A.lead(share(62, 98), share(10, 230)), "15×", "10 of each: shown; 14.55 is 15")
        # one decimal under 10, half up on the exact ratio
        self.assertEqual(A.lead(share(89, 98), share(49, 230)), "4.3×")
        self.assertEqual(
            A.lead(share(45, 100), share(20, 100)), "2.3×", "2.25 is 2.3, half up, where Python's round gives 2.2"
        )
        self.assertEqual(A.lead(share(40, 100), share(20, 100)), "2.0×")
        self.assertEqual(A.lead(share(29, 40), share(10, 200)), "15×", "14.5 is 15")
        # from 10 a whole number: 9.95 rounds to 10.0, and reads 10×
        self.assertEqual(A.lead(share(199, 200), share(20, 200)), "10×")
        self.assertEqual(A.lead(share(197, 200), share(20, 200)), "9.9×", "9.85 is 9.9")
        self.assertEqual(A.MIN_LEAD, 10)

    def test_short_count(self):
        """How the size thresholds of By context are printed: "< 2.4k files" and "> 6.7k files"."""
        self.assertEqual(A.short_count(2350), "2.4k")
        self.assertEqual(A.short_count(3149), "3.1k")
        self.assertEqual(A.short_count(11000), "11k")
        self.assertEqual(A.short_count(12345), "12k")
        self.assertEqual(A.short_count(999.6), "1k")
        self.assertEqual(A.short_count(640), "640")
        self.assertEqual(A.short_count(107.6), "110")
        self.assertEqual(A.short_count(9), "9")

    def test_month_name(self):
        self.assertEqual(A.month_name("2026-08-17"), "Aug")
        self.assertEqual(A.month_name("2026-08-17", year=True), "Aug 2026")
        self.assertEqual(A.month_name("2025-01"), "Jan")
        self.assertEqual(A.month_name("2025-12-17", year=True), "Dec 2025")


class Banner(unittest.TestCase):
    """The banner names four organisations of the pro scene: the build stops, saying which, when
    one has no repo left there or its owner is not an organisation."""

    PRO = [
        {"name": name, "facts": {"owner_type": "Organization"}}
        for name in ("huggingface/transformers", "n8n-io/n8n", "Supabase/supabase", "bluesky-social/atproto", "other/x")
    ]

    def test_the_four_owners_in_the_pro_scene_give_the_text(self):
        said = A.banner(self.PRO)
        self.assertEqual(list(said), ["lead", "body"])
        self.assertIn("like Hugging Face, n8n, Supabase, Bluesky, to uncover", "".join(s["text"] for s in said["body"]))
        self.assertEqual([s["text"] for s in said["body"] if s["org"]], ["Hugging Face", "n8n", "Supabase", "Bluesky"])

    def test_an_owner_with_no_pro_repo_left_stops_the_build(self):
        for gone in ("huggingface", "n8n-io", "supabase", "bluesky-social"):
            pro = [r for r in self.PRO if r["name"].split("/")[0].lower() != gone]
            with self.assertRaisesRegex(ValueError, r"\(%s\), which has no repo left in the pro scene" % gone):
                A.banner(pro)

    def test_an_owner_that_is_not_an_organisation_stops_the_build(self):
        pro = [dict(r, facts={"owner_type": "User"}) if r["name"] == "n8n-io/n8n" else r for r in self.PRO]
        with self.assertRaisesRegex(ValueError, r"n8n \(n8n-io\), whose owner is not an organisation"):
            A.banner(pro)


class Intros(unittest.TestCase):
    """The intro of Test and of Secure, counted from whatever practices the section holds, naming none, so that it stays
    true when a practice is added or removed; one practice, or none, has its own words."""

    @staticmethod
    def item(kind="any", k=50, first=None, n=100):
        return {
            "kind": kind,
            "history": first is not None,
            "pro": {
                "now": {"k": k, "n": n, "p": k / n},
                "first": None if first is None else {"k": first, "n": n, "p": first / n},
            },
        }

    def test_counts(self):
        i = self.item
        self.assertEqual(
            A.counts_line([i("agent", 60, 10), i("any", 51, 45), i("any", 50, 30), i("any", 20)], "January 2025"),
            "Of the 4 practices here, 1 is made for coding agents. 2 are in more than half of the pro repos. Of the 3 read since "
            "January 2025, 2 have gained 10 points or more in the pro scene.",
        )
        self.assertEqual(
            A.counts_line([i("agent", 9, 0), i("agent", 30, 29)], "January 2025"),
            "All 2 practices here are made for coding agents. None are in more than half of the pro repos. Since January 2025, "
            "none have gained 10 points or more in the pro scene.",
        )
        self.assertEqual(
            A.counts_line([i("any", 60, 50), i("any", 30), i("any", 70, 69)], "January 2025"),
            "None of the 3 practices here is made for coding agents. 2 are in more than half of the pro repos. Of the 2 read since "
            "January 2025, 1 has gained 10 points or more in the pro scene.",
        )
        self.assertEqual(
            A.counts_line([i("any", 60, 50), i("agent", 30), i("agent", 70)], "January 2025"),
            "Of the 3 practices here, 2 are made for coding agents. 2 are in more than half of the pro repos. The one read since "
            "January 2025 has gained 10 points or more in the pro scene.",
        )
        # no practice read at the first snapshot: no sentence of what changed since
        self.assertEqual(
            A.counts_line([i("any", 60), i("agent", 30)], "January 2025"),
            "Of the 2 practices here, 1 is made for coding agents. 1 is in more than half of the pro repos.",
        )

    def test_one_practice_or_none(self):
        self.assertEqual(
            A.counts_line([self.item("agent", 30, 25)], "January 2025"),
            "Its one practice is made for coding agents, and is in 30 of 100 pro repos. Since January 2025 it has not gained 10 "
            "points or more in the pro scene.",
        )
        self.assertEqual(
            A.counts_line([self.item("any", 30)], "January 2025"),
            "Its one practice is not made for coding agents, and is in 30 of 100 pro repos.",
        )
        self.assertEqual(A.counts_line([], "January 2025"), "")

    def test_kinds(self):
        """Build's and Ship's sentence of kinds counts the practices made for coding agents and no others. It is the
        sentence counts_line opens Test's and Secure's intros with."""
        i = self.item
        self.assertEqual(
            A.kinds_line([i("agent"), i("agent"), i("any")]), "Of the 3 practices here, 2 are made for coding agents."
        )
        self.assertEqual(A.kinds_line([i("agent"), i("any")]), "Of the 2 practices here, 1 is made for coding agents.")
        self.assertEqual(A.kinds_line([i("agent"), i("agent")]), "All 2 practices here are made for coding agents.")
        self.assertEqual(A.kinds_line([i("any"), i("any")]), "None of the 2 practices here is made for coding agents.")
        self.assertEqual(A.kinds_line([i("agent")]), "Its one practice is made for coding agents.")
        self.assertEqual(A.kinds_line([i("any")]), "Its one practice is not made for coding agents.")
        for items in ([i("agent"), i("any"), i("any", 60)], [i("any", 60), i("agent", 30)]):
            self.assertTrue(A.counts_line(items, "January 2025").startswith(A.kinds_line(items) + " "))

    def test_a_gain_is_the_difference_of_the_shares_as_printed(self):
        # 21% then 30.5%: 21% and 31% as printed, 10 points, though the unrounded shares are 9.5 apart (a change in
        # points is the difference of the two shares as printed, so a change and the shares beside it subtract)
        self.assertEqual(
            A.counts_line([self.item("any", 61, 42, 200), self.item("any", 10, None, 200)], "January 2025").split(". ")[
                -1
            ],
            "The one read since January 2025 has gained 10 points or more in the pro scene.",
        )
        self.assertEqual(
            A.counts_line([self.item("any", 61, 43, 200), self.item("any", 10, None, 200)], "January 2025").split(". ")[
                -1
            ],
            "The one read since January 2025 has not gained 10 points or more in the pro scene.",
        )


class Basics(unittest.TestCase):
    """The rule of the Basics on inputs worked out by hand: a practice not specific to AI that half of the pro scene or more had
    18 months before the last snapshot, or today when it has no monthly history."""

    MONTHLY = ["%d-%02d-17" % (2025 + (m - 1) // 12, (m - 1) % 12 + 1) for m in range(1, 24)]  # Jan 2025 to Nov 2026

    @staticmethod
    def item(kind="any", series=None, k=0, n=10):
        pro = dict(
            {"now": {"k": k, "n": n, "p": k / n}}, **({} if series is None else {"series": [x / n for x in series]})
        )
        return {"kind": kind, "history": series is not None, "pro": pro}

    def test_the_constants(self):
        self.assertEqual((A.BASIC_MONTHS, A.BASIC_SHARE), (18, 0.5))

    def test_the_reference_is_18_months_before_the_last_snapshot(self):
        self.assertEqual(self.MONTHLY[A.basic_at(self.MONTHLY)], "2025-05-17")
        # a day of the month past the reference's: the snapshot before it
        self.assertEqual(A.basic_at(["2025-05-18", "2025-06-17", "2026-11-17"]), 0)
        self.assertEqual(A.basic_at(["2025-04-30", "2025-05-18", "2026-11-17"]), 0)
        self.assertEqual(A.basic_at(["2025-04-30", "2025-05-17", "2026-11-17"]), 1)
        # the 31st, 18 months back into a month of 30 days: its last day
        self.assertEqual(A.basic_at(["2024-11-30", "2024-12-01", "2026-05-31"]), 0)
        # it rolls with the run: a month later, a month later
        self.assertEqual(self.MONTHLY[A.basic_at(self.MONTHLY[:-1])], "2025-04-17")

    def test_on_the_page_s_grid_the_reference_is_its_first_date(self):
        """The page's grid starts at the rule's window start, panel.ROLL_MONTHS back: while the Basics look as
        far back, their reference is the grid's first date, the same day as the rule's, though the two are two numbers."""
        dates = [d.isoformat() for d in A.grid()]
        self.assertEqual(A.panel.ROLL_MONTHS, A.BASIC_MONTHS)
        self.assertEqual(A.basic_at(dates), 0)
        self.assertEqual(dates[A.basic_at(dates)], A.panel.rule(A.AS_OF)["window_start"])

    def test_a_short_history_is_judged_at_the_first_snapshot(self):
        dates = self.MONTHLY[-6:]
        self.assertEqual(A.basic_at(dates), 0)
        at = A.basic_at(dates)
        self.assertTrue(A.is_basic(self.item(series=[5, 5, 5, 5, 5, 5], k=5), at))
        self.assertFalse(A.is_basic(self.item(series=[4, 5, 6, 7, 8, 9], k=9), at))

    def test_exactly_half_is_a_basic(self):
        at = A.basic_at(self.MONTHLY)
        half = [0] * 23
        half[at] = 5
        self.assertTrue(A.is_basic(self.item(series=half, k=0), at))
        under = [0] * 23
        under[at] = 4
        self.assertFalse(A.is_basic(self.item(series=under, k=10), at), "today's share does not count with a history")
        # an odd base: 104 of 209 is under half, 105 is over
        self.assertFalse(A.is_basic(self.item(series=[104] * 23, k=209, n=209), at))
        self.assertTrue(A.is_basic(self.item(series=[105] * 23, k=0, n=209), at))

    def test_no_history_is_judged_today(self):
        self.assertTrue(A.is_basic(self.item(k=5), 4))
        self.assertFalse(A.is_basic(self.item(k=4), 4))

    def test_a_practice_made_for_agents_is_never_a_basic(self):
        self.assertFalse(A.is_basic(self.item("agent", series=[10] * 23, k=10), 4))
        self.assertFalse(A.is_basic(self.item("agent", k=10), 4))

    def test_the_intros_count_the_list_the_page_shows_first(self):
        items = [
            dict(i, basic=b) for i, b in ((Intros.item("any", 60, 50), True), (Intros.item("agent", 30, 20), False))
        ]
        got = A.basics_intros(items, A.kinds_line)
        self.assertEqual(got["intro"], "Its one practice is made for coding agents.")
        self.assertEqual(got["intro_all"], "Of the 2 practices here, 1 is made for coding agents.")

    def test_the_rule_is_written_from_its_numbers(self):
        items = [{"id": "a", "basic": True}, {"id": "b", "basic": False}]
        got = A.basics_section(items, self.MONTHLY, A.basic_at(self.MONTHLY))
        self.assertEqual((got["ids"], got["ref"], got["months"], got["share"]), (["a"], "2025-05-17", 18, 0.5))
        self.assertEqual(
            got["rule"],
            "A Basic is a practice not specific to AI that half of the pro scene or more already had 18 months ago, in May "
            "2025. One read today only, with no monthly history, is a Basic when half of the pro scene or more has it today.",
        )
        self.assertEqual(got["tip"], "Practices that 50%+ of the pro scene already had 18 months ago.")
        short = A.basics_section(items, self.MONTHLY[-6:], 0)
        self.assertIn("already had at the first snapshot, 5 months ago, in June 2026.", short["rule"])
        self.assertEqual(
            short["tip"], "Practices that 50%+ of the pro scene already had at the first snapshot, 5 months ago."
        )


class Series(unittest.TestCase):
    def test_series_counts_the_whole_panel(self):
        # c has no state at snapshots 0 to 2: it is in the base and does not have it
        got = [(x["k"], x["n"]) for x in A.series(repos(), "x")]
        self.assertEqual(got, [(2, 6), (3, 6), (3, 6), (3, 6), (4, 6), (3, 6)])

    def test_one_base_and_the_last_point_is_today(self):
        got = A.series(repos(), "x")
        self.assertEqual({x["n"] for x in got}, {len(X)})
        self.assertEqual(got[-1]["k"], sum(1 for r in repos() if r["now"]["x"]))

    def test_retention(self):
        # had it at snapshot 0, 1 or 2: a, b, d, f. Still have it: a.
        self.assertEqual(A.BACK, 3)
        got = A.retention(repos(), "x")
        self.assertEqual((got["k"], got["n"]), (1, 4))

    def test_moves(self):
        # snapshot 2 against 5, over the whole panel: c (created since) and e gained it, d and f lost it
        self.assertEqual(A.moves(repos(), "x"), {"gained": 2, "lost": 2, "new": 1})

    def test_today_is_then_plus_the_adds_less_the_removals(self):
        s, mv = A.series(repos(), "x"), A.moves(repos(), "x")
        self.assertEqual(s[-1]["k"], s[-1 - A.BACK]["k"] + mv["gained"] - mv["lost"])
        self.assertLessEqual(mv["new"], mv["gained"])

    def test_a_new_repo_without_it_today_is_no_move(self):
        rs = repos()
        # c, created since, had it for a month and not today
        rs[2]["f"] = [None if x is None else {"x": x} for x in (None, None, None, F, T, F)]
        rs[2]["now"] = rs[2]["f"][-1]
        self.assertEqual(A.moves(rs, "x"), {"gained": 1, "lost": 2, "new": 0})

    def test_new_since(self):
        self.assertEqual([A.new_since(repos(), i) for i in range(6)], [1, 1, 1, 0, 0, 0])
        self.assertFalse(A.has(None, "x"))
        self.assertTrue(A.has({"x": True}, "x"))

    def test_change_is_the_difference_of_the_shares_as_printed(self):
        # 79.39% to 66.67% printed 79% and 67%: the change is -12, where the unrounded difference rounds to -13;
        # 22.45% to 26.53%, printed 22% and 27%, is +5 where the unrounded difference rounds to +4
        s = lambda then, now: [then] + [0] * (A.BACK - 1) + [now]
        self.assertEqual(A.change(s(0.7939, 0.6667)), -12)
        self.assertEqual(A.change(s(0.2245, 0.2653)), 5)
        self.assertEqual(A.change(s(0.0043, 0.0)), 0, "<1% to 0%: the same printed share")
        self.assertEqual(
            [A.points(p) for p in (0.005, 0.0049, 0.125, 0.995)], [1, 0, 13, 100], "half up, as the page's Math.round"
        )

    def test_the_order_of_what_moved(self):
        """The largest rise in points first, as printed; then the larger change in repos; then the more repos that added
        it; a move of fewer than SHOWN_MOVE pro repos either way is not a row, nor a lens practice that may not move."""

        def item(key, change, gained, lost, **extra):
            return dict(
                {
                    "id": key,
                    "history": True,
                    "pro": {"change": change, "moves": {"gained": gained, "lost": lost, "new": 0}},
                },
                **extra,
            )

        rows = [
            item("a", 4, 4, 0),
            item("b", 5, 5, 0),
            item("c", 5, 6, 1),
            item("d", 5, 6, 0),
            item("e", -12, 0, 12),
            item("f", 1, 2, 1),
            item("g", 9, 9, 0, in_moves=False),
            item("h", 0, 4, 4),
            dict(item("i", 3, 3, 0), history=False),
        ]
        self.assertEqual(A.moved(rows), ["d", "c", "b", "a", "h", "e"])  # d: a net of 6; c before b: more added

    def test_departures(self):
        ever, gone, when = A.departures(repos(), lambda r: [f and f["x"] for f in r["f"]])
        # every repo had it at some snapshot: e, which only has it today, counts too
        self.assertEqual(ever, 6)
        # what is left once the leavers are out is today's count: a, c and e
        self.assertEqual(ever - len(gone), sum(1 for r in repos() if r["now"]["x"]))
        self.assertEqual(sorted(r["name"] for r in gone), ["b", "d", "f"])
        self.assertEqual(when, [0, 0, 1, 0, 0, 2])


class Left(unittest.TestCase):
    def test_left_rows(self):
        keys = [k for k, _, history, _ in A.ITEMS if history]
        rs = repos("claude_md", {k: False for k in keys})
        # f keeps an AGENTS.md today; a had Cursor rules at the first snapshot only
        rs[-1]["now"] = dict(rs[-1]["now"], agents_md=True)
        cursor = {"cursor_rules": {"n": 1, "root": 1, "shipped": 0, "symlink": 0, "sample": [".cursorrules"]}}
        for r in rs:
            sets = [{"hits": {}}, {"hits": cursor}]
            first = 1 if r["name"] == "a" else 0
            r["scan"] = {
                "sets": sets,
                "snaps": [None if f is None else {"set": first if i == 0 else 0} for i, f in enumerate(r["f"])],
            }
        # the practices of A.ITEMS with a history, as main() counts them (count_practice): llms.txt has no row
        # (NO_KEEP_RATE)
        items = [
            {
                "id": k,
                "label": A.LABEL[k],
                "field": A.PRACTICES[k][0],
                "kind": A.PRACTICES[k][1],
                "about": A.ABOUT[k],
                "in_moves": True,
            }
            for k in keys
        ]
        rows = A.left(rs, items, A.TOOL_FILES)
        self.assertEqual([row["id"] for row in rows], ["claude_md", "cursor_rules"])
        claude, cursor = rows
        self.assertEqual((claude["left"]["k"], claude["left"]["n"]), (3, 6))
        self.assertEqual(claude["when"], [0, 0, 1, 0, 0, 2])
        self.assertEqual(claude["after"], "1 of the 3 have an AGENTS.md today")
        self.assertEqual((cursor["left"]["k"], cursor["left"]["n"]), (1, 1))
        self.assertEqual(cursor["when"], [0, 1, 0, 0, 0, 0])
        self.assertNotIn("after", cursor, "under 3 leavers: no sentence")


class Grid(unittest.TestCase):
    """The page's grid: the monthly dates from the rule's window start to the last snapshot.
    A scan holds the whole grid of common.snapshot_dates; the analysis reads it from the window's start, and a repo with no state
    there fails it loudly."""

    @staticmethod
    def scan(first=None):
        full = A.snapshot_dates()
        snaps = [{"date": d.isoformat(), "set": 0} for d in full]
        if first:
            snaps = [None if d < first else s for d, s in zip(full, snaps)]
        return {"name": "o/r", "snaps": snaps, "sets": []}

    def test_the_grid_starts_at_the_window_s_start(self):
        grid, full = A.grid(), A.snapshot_dates()
        self.assertEqual(grid[0], A.WINDOW_START)
        self.assertEqual(len(grid), A.panel.ROLL_MONTHS + 1)
        self.assertEqual(full[-len(grid) :], grid)
        self.assertEqual(
            full[: len(full) - len(grid) + 1], [dt.date.fromisoformat(d) for d in A.panel.rule(A.AS_OF)["windows"]]
        )

    def test_a_scan_is_cut_to_the_grid(self):
        got = A.on_grid(self.scan())
        self.assertEqual([s["date"] for s in got["snaps"]], [d.isoformat() for d in A.grid()])
        # a repo born after the scans' first date and before the window's start: the dates before it are not read
        later = A.snapshot_dates()[2]
        self.assertEqual(A.on_grid(self.scan(first=later))["snaps"][0]["date"], A.WINDOW_START.isoformat())
        self.assertEqual(A.on_grid(self.scan(first=A.WINDOW_START))["snaps"][0]["date"], A.WINDOW_START.isoformat())

    def test_no_state_at_the_window_s_start_is_kept_and_none_at_the_last_fails(self):
        """A repo whose default branch's history starts after the window's start has no state at the first dates: it is kept,
        and counts there as without every practice (the fixed panel); one with no state at the last snapshot fails."""
        got = A.on_grid(self.scan(first=A.grid()[1]))
        self.assertEqual([s is None for s in got["snaps"][:2]], [True, False])
        with self.assertRaisesRegex(ValueError, "has no state at %s, the last snapshot" % A.AS_OF):
            A.on_grid(self.scan(first=A.AS_OF + dt.timedelta(days=1)))

    def test_a_scan_of_another_grid_fails(self):
        scan = self.scan()
        with self.assertRaisesRegex(ValueError, "not on the grid"):
            A.on_grid(dict(scan, snaps=scan["snaps"][1:]))
        moved = [dict(s, date=s["date"][:8] + "18") for s in scan["snaps"]]
        with self.assertRaisesRegex(ValueError, "not on the grid"):
            A.on_grid(dict(scan, snaps=moved))

    def test_an_event_before_the_window_s_start_is_off_the_page(self):
        dates = [d.isoformat() for d in A.grid()]
        before = (A.WINDOW_START - dt.timedelta(days=31)).isoformat()[:7]
        self.assertFalse(A.in_grid(before, dates))
        self.assertTrue(A.in_grid(dates[0][:7], dates))
        self.assertTrue(A.in_grid(dates[-1][:7], dates))
        self.assertEqual(
            [m for m, _, _ in A.EVENTS if not A.in_grid(m, dates)], [m for m, _, _ in A.EVENTS if m < dates[0][:7]]
        )


class Models(unittest.TestCase):
    def test_both_counts_are_over_the_months_of_the_grid(self):
        """A scan holds the months of its whole history, which starts before the first snapshot of the page: a commit of a month
        off the grid is in neither count, the commits that only say Claude included. The grid starts at the rule's window start,
        so the months of the scan's first snapshots, which the rule reads, are off it too."""
        first = A.grid()[0].isoformat()[:7]
        self.assertEqual(A.grid()[0], A.WINDOW_START)
        self.assertEqual(A.WINDOW_START.isoformat(), A.panel.rule(A.AS_OF)["window_start"])
        self.assertEqual(first, "2025-05")
        scanned = A.snapshot_dates()[0].isoformat()[:7]  # the scans' first snapshot, before the window's start
        self.assertLess(scanned, first)
        models = {
            "2024-10 claude": 5,
            "2024-12 claude": 3,
            "2024-12 opus 4.5": 7,
            scanned + " claude": 11,
            scanned + " opus 4.5": 13,
            first + " claude": 2,
            first + " opus 4.5": 30,
            "2026-11 claude": 1,
            "2026-11 opus 4.5": 4,
        }
        # in five repos, as a model row asks (MODEL_REPOS)
        got = A.model_history(
            {"pro": [{"name": "o/r%d" % i, "scan": {"models": models}} for i in range(5)], "ladder": []}
        )
        self.assertEqual(got["months"][0], first)
        self.assertEqual((got["named"], got["unnamed"]), (5 * 34, 5 * 3))
        self.assertEqual(got["rows"][0]["commits"], 5 * 34)
        self.assertEqual(A.month_name(first, year=True, full=True), "May 2025")
        self.assertEqual(A.month_name(first, year=True), "May 2025")

    def test_a_made_up_model_name_is_not_a_row(self):
        """A display name is typed by whoever commits: one ladder repo signing its commits "Claude Opus 9" could put a
        model on the page. A row is a name of the form Claude Code writes, in 5 repos or more; the commits of any other
        name stay in the month's total."""
        month = A.snapshot_dates()[-1].isoformat()[:7]
        real = [{"name": "o/r%d" % i, "scan": {"models": {month + " opus 4.5": 30}}} for i in range(5)]
        one = {"name": "o/fake", "scan": {"models": {month + " opus 9": 500}}}
        odd = [{"name": "o/odd%d" % i, "scan": {"models": {month + " codex opus 4.8": 100}}} for i in range(5)]
        got = A.model_history({"pro": real + odd, "ladder": [one]})
        self.assertEqual([row["name"] for row in got["rows"]], ["Opus 4.5"])
        self.assertEqual(got["named"], 150 + 500 + 500)


if __name__ == "__main__":
    unittest.main()
