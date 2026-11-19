"""
    CLI orchestration file. Contains the command line interface
    installed as `pcfuzz`. It orchestrates the settings matrix run, loading the settings
    YAML file, generating the mutations, sending the requests, evaluating the
    responses, and writing the results to CSV and JSON files.
    
    Usage:
        pcfuzz run --matrix <settings.yaml> --out <results_dir>
        pcfuzz techniques
"""

# IMPORTS
from __future__ import annotations
import argparse
import sys
from pathlib import Path
import yaml

from . import mutations
from .oracle import evaluate_response
from .report import ResultRow, print_table, write_csv, write_json
from .transport import RawRequest, send_raw


def _load_settings(path: Path) -> dict:
    '''
        Load the settings YAML file and return it as a dictionary.
    '''
    return yaml.safe_load(path.read_text(encoding="utf-8"))

def cmd_run(args: argparse.Namespace) -> int:
    '''
        Run a matrix pass, sending raw mutated requests to the target and evaluating
        the responses. Write the results to CSV and JSON files.
    '''
    matrix = _load_settings(Path(args.matrix))
    
    base_paths = matrix["base_paths"]
    secret = matrix.get("secret_marker", "")
    protected = matrix.get("protected_prefix", "/admin")
    techniques = args.techniques.split(",") if args.techniques else None

    # Context threaded into the generators (no hardcoded endpoints there)
    ctx = mutations.MutationContext(
        protected_prefix=protected,
        injection_target=matrix.get("injection_target", protected),
    )

    # Generate mutations for each base path and technique
    # (max_depth > 1 also yields combinations of techniques)
    muts = list(mutations.generate(base_paths, techniques, ctx=ctx, max_depth=args.depth))

    # Which pairs will run (respecting --pair)
    selected = [p for p in matrix["pairs"] if not args.pair or p["name"] == args.pair]
    total = len(muts) * len(selected)

    # Build a single result row for one (pair, mutation)
    def _process(pair: dict, mut: mutations.Mutation) -> ResultRow:
        extra = {"x-middleware-subrequest": "1"} if args.header_trust else {}
        try:
            request = RawRequest(base_url=pair["base_url"], raw_target=mut.raw_target,
                                 extra_headers=extra, timeout=args.timeout)
            resp = send_raw(request)
        except OSError as e:
            return ResultRow(
                pair["name"], pair.get("edge", "?"), pair.get("backend", "?"),
                mut.base_path, mut.technique, mut.label, mut.raw_target,
                0, "?", "?", "BLAD", "", str(e))

        verdict = evaluate_response(resp, mut.base_path, secret, protected)
        return ResultRow(
            pair["name"], pair.get("edge", "?"), pair.get("backend", "?"),
            mut.base_path, mut.technique, mut.label, mut.raw_target,
            verdict.http_status, verdict.edge_decision, verdict.edge_path,
            verdict.summary,
            ",".join(f.rule for f in verdict.findings),
            "; ".join(f.detail for f in verdict.findings))

    # Start banner (progress goes to stderr so stdout stays clean for the summary)
    def _log(msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    tech_label = args.techniques if args.techniques else "all"
    _log(f"[start] matrix={args.matrix} pairs={len(selected)} "
         f"mutations/pair={len(muts)} techniques={tech_label} depth={args.depth} "
         f"total_requests={total}")

    # Run the matrix, reporting progress as we go
    rows: list[ResultRow] = []
    try:
        from rich.progress import (Progress, BarColumn, TextColumn,
                                    MofNCompleteColumn, TimeElapsedColumn)
        with Progress(TextColumn("[progress.description]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn()) as prog:
            task = prog.add_task("fuzzing", total=total)
            for pair in selected:
                prog.update(task, description=f"{pair['name']} ({pair['base_url']})")
                for mut in muts:
                    row = _process(pair, mut)
                    rows.append(row)
                    prog.advance(task)
                    if "R1" in row.rules:
                        prog.console.print(f"  [bold red]R1 bypass[/] {pair['name']}  {row.raw_target}")
    except ImportError:
        # plain fallback: periodic counter on stderr
        done = 0
        for pair in selected:
            _log(f"[pair] {pair['name']} -> {pair['base_url']}")
            for mut in muts:
                row = _process(pair, mut)
                rows.append(row)
                done += 1
                if "R1" in row.rules:
                    _log(f"  R1 bypass {pair['name']}  {row.raw_target}")
                if done % 100 == 0 or done == total:
                    _log(f"  {done}/{total}")

    _log(f"[done] {len(rows)} requests sent")

    # Write the results to CSV and JSON files
    # and write nicely formatted results to stdout
    output_dir = Path(args.out)
    if rows:
        write_json(rows, output_dir)
        write_csv(rows, output_dir)

    print_table(rows)
    print(f"\n{len(rows)} results. Catalogue: {output_dir}/catalogue.csv, {output_dir}/catalogue.json")

    return 0


def cmd_techniques(_args: argparse.Namespace) -> int:
    '''
        List available mutation techniques.
    '''
    for t in mutations.list_techniques():
        print(t)
    return 0


def main(argv: list[str] | None = None) -> int:
    '''
        Main entry point for the CLI. Parses arguments and dispatches command.
    '''

    ap = argparse.ArgumentParser(prog="pcfuzz", description="differential path-confusion fuzzer")
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run a matrix pass")
    run.add_argument("--matrix", required=True)
    run.add_argument("--out", default="results")
    run.add_argument("--pair", default=None, help="run only this pair")
    run.add_argument("--techniques", default=None, help="csv of techniques (default: all)")
    run.add_argument("--depth", type=int, default=1,
                     help="combination depth: 1 = single techniques, 2 = pairs, ...")
    run.add_argument("--timeout", type=float, default=5.0)
    run.add_argument("--header-trust", action="store_true",
                     help="add x-middleware-subrequest")
    run.set_defaults(func=cmd_run)

    techniques = sub.add_parser("techniques", help="list available mutation techniques")
    techniques.set_defaults(func=cmd_techniques)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
