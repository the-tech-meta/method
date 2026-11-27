"""What the tests share: the paths, the files as they are on disk, and the run date.

Some files are not in every checkout: the page's source (site/), the scans and API signals (data/scan, data/api) and
data/meta.json. A test that needs one is skipped when it is absent: see needs().

The run date is given to the pipeline (METATECH_AS_OF) before any module is imported: common.py fixes AS_OF at import,
and without it AS_OF would be today. It is the run date of data/meta.json when that file is there. Without it, the tests
need only the day of the month, because the grid of snapshots falls on the run's day: the day of the rule's first
snapshot (rule.first_day in data/panel_rule.json). So it is today's date moved to that day.
"""

import datetime
import decimal
import functools
import json
import os
import sys
import unittest
from pathlib import Path

PIPELINE = Path(__file__).resolve().parent.parent
ROOT = PIPELINE.parent
DATA = ROOT / "data"
SITE = ROOT / "site"


def text(path):
    """A file's text, or "" when the file is not in this checkout."""
    return path.read_text() if path.exists() else ""


# The page's source, three files: the markup (with the two scripts that stay inline: the theme
# kept by the reader and the data's mark), the styles and the page's script.
MARKUP = text(SITE / "template.html")
STYLES = text(SITE / "page.css")
SCRIPT = text(SITE / "page.js")
SOURCES = {"site/template.html": MARKUP, "site/page.css": STYLES, "site/page.js": SCRIPT}
sys.path.insert(0, str(PIPELINE))


def read(path):
    with open(path) as f:
        return json.load(f)


def needs(path, what=None):
    """A unittest.skipUnless decorator: the test runs when `path` (a Path under the root) exists."""
    rel = path.relative_to(ROOT).as_posix()
    return unittest.skipUnless(path.exists(), "needs %s, which this checkout does not hold" % (what or rel))


@functools.lru_cache(maxsize=None)
def meta():
    return read(DATA / "meta.json")


if (DATA / "meta.json").exists():
    os.environ.setdefault("METATECH_AS_OF", meta()["as_of"])
else:
    early_day = datetime.date.fromisoformat(read(DATA / "panel_rule.json")["rule"]["first_day"])
    os.environ.setdefault("METATECH_AS_OF", datetime.date.today().replace(day=early_day.day).isoformat())


def method(copy=None):
    """The blocks of the Method tab by title, from copy.method (its sections in order, each a list of blocks: analyze.block)."""
    copy = copy or meta()["copy"]
    return {b["title"]: b for blocks in copy["method"].values() for b in blocks}


def said(b):
    """Every word of a Method block, its parts in the page's order: the lead, the table's terms and definitions, the bullets, then
    the disclosure's label, lead, part titles and bullets."""
    more = b.get("more") or {"label": "", "parts": []}
    return " ".join(
        x
        for x in [b.get("lead", "")]
        + [" ".join(row) for row in b.get("rows", [])]
        + b.get("items", [])
        + [more["label"], more.get("lead", "")]
        + [y for part in more["parts"] for y in [part.get("title") or ""] + part["items"]]
        if x
    )


@functools.lru_cache(maxsize=None)
def panel(league):
    return read(DATA / ("panel_%s.json" % league))


@functools.lru_cache(maxsize=None)
def scan(name):
    path = DATA / "scan" / (name.replace("/", "__") + ".json")
    return read(path) if path.exists() else None


@functools.lru_cache(maxsize=None)
def api(name):
    path = DATA / "api" / (name.replace("/", "__") + ".json")
    return read(path) if path.exists() else None


def league(name):
    """The repos of one panel that the analysis reads: those with a scan and an API file."""
    return [r for r in panel(name) if scan(r["name"]) and api(r["name"])]


MIN_LEAD = 10  # repos of each league with a practice for its pro lead to be shown


def lead(pro_k, pro_n, ladder_k, ladder_n):
    """The pro lead, written again from its definition for the recounts: the pro share over the ladder's, from the four
    counts, rounded half up to one decimal under 10 and to a whole number from 10;
    None unless both counts are MIN_LEAD or more."""
    if pro_k < MIN_LEAD or ladder_k < MIN_LEAD:
        return None
    with decimal.localcontext() as ctx:
        ctx.prec = 40
        ratio = decimal.Decimal(pro_k * ladder_n) / decimal.Decimal(pro_n * ladder_k)
        tenth = ratio.quantize(decimal.Decimal("0.1"), rounding=decimal.ROUND_HALF_UP)
        if tenth < 10:
            return "%s×" % tenth
        return "%s×" % ratio.quantize(decimal.Decimal("1"), rounding=decimal.ROUND_HALF_UP)


def shares(obj, where="meta"):
    """Every share in a part of meta.json, with where it sits: a dict with k, n and p."""
    if isinstance(obj, dict):
        if {"k", "n", "p"} <= set(obj):
            yield where, obj
        for key, value in obj.items():
            yield from shares(value, "%s.%s" % (where, key))
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from shares(value, "%s[%d]" % (where, i))
