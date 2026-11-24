"""The pure functions of analyze.py on small inputs worked out by hand."""

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


class Models(unittest.TestCase):
    def test_both_counts_are_over_the_months_of_the_grid(self):
        """A scan holds the months of its whole history, which starts before the first snapshot: a commit of a month off
        the grid is in neither count, the commits that only say Claude included."""
        first = A.snapshot_dates()[0].isoformat()[:7]
        self.assertEqual(first, "2025-01")
        models = {
            "2024-10 claude": 5,
            "2024-12 claude": 3,
            "2024-12 opus 4.5": 7,
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
        self.assertEqual(A.month_name(first, year=True, full=True), "January 2025")
        self.assertEqual(A.month_name(first, year=True), "Jan 2025")

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
