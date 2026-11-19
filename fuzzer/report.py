"""Reporting: mutation x pair catalog, CSV/JSON export, terminal table, metrics."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class ResultRow:
    pair: str
    edge: str
    backend: str
    base_path: str
    technique: str
    label: str
    raw_target: str
    http_status: int
    edge_decision: str
    edge_path: str
    verdict: str
    rules: str
    detail: str


def write_json(rows: list[ResultRow], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "catalogue.json"
    p.write_text(json.dumps([asdict(r) for r in rows], indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def write_csv(rows: list[ResultRow], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "catalogue.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()) if rows else ["pair"])
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))
    return p


def metrics(rows: list[ResultRow]) -> dict[str, dict]:
    per_pair: dict[str, dict] = {}
    for r in rows:
        d = per_pair.setdefault(r.pair, {"total": 0, "divergent": 0, "bypass": 0})
        d["total"] += 1
        # decoupled from verdict wording: a row is divergent iff it has findings
        if r.rules:
            d["divergent"] += 1
        if "R1" in r.rules:
            d["bypass"] += 1
    for d in per_pair.values():
        d["divergent_pct"] = round(100 * d["divergent"] / d["total"], 1) if d["total"] else 0.0
    return per_pair


def _is_interesting(r: ResultRow) -> bool:
    # show rows that carry findings or that errored; hide clean agreements
    return bool(r.rules) or r.verdict == "BLAD"


def print_table(rows: list[ResultRow]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for r in rows:
            if _is_interesting(r):
                print(f"{r.pair:14} {r.technique:16} {r.verdict:22} {r.raw_target}")
        return

    console = Console()
    t = Table(title="Divergences (edge x backend)")
    for col in ("pair", "technique", "verdict", "status", "request-target"):
        t.add_column(col, overflow="fold")
    any_div = False
    for r in rows:
        if not _is_interesting(r):
            continue
        any_div = True
        style = "bold red" if "R1" in r.rules else "yellow"
        t.add_row(r.pair, r.technique, f"[{style}]{r.verdict}[/]", str(r.http_status), r.raw_target)
    if any_div:
        console.print(t)
    else:
        console.print("[green]No divergences (all agreements).[/]")

    mt = Table(title="Metrics per pair")
    for col in ("pair", "mutations", "divergent", "% divergent", "bypass (R1)"):
        mt.add_column(col)
    for pair, d in metrics(rows).items():
        mt.add_row(pair, str(d["total"]), str(d["divergent"]), f'{d["divergent_pct"]}%', str(d["bypass"]))
    console.print(mt)
