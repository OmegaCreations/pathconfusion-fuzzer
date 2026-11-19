"""
    URI mutation engine.

    Each mutation carries a technique label (for the result catalog). Generators are
    composable. generate() always yields the identity variant
    first per base path (the baseline the control group checks).
"""

# imports
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator


@dataclass(frozen=True)
class MutationContext:
    '''
        Config threaded into generators so they do not hardcode endpoints.
        Values come from matrix.yml (see cli.py).
    '''
    protected_prefix: str = "/admin"
    injection_target: str = "/admin/secret"


@dataclass(frozen=True)
class Mutation:
    '''
        A single mutation of a base path.
    '''
    technique: str
    label: str
    raw_target: str
    base_path: str


def _both_cases(code: str) -> list[str]:
    '''
        Return the lower- and upper-case form of a percent-encoding.

        e.g. "%2e" -> ["%2e", "%2E"]; "%20" -> ["%20"] (no hex letters to vary)
    '''
    lo, hi = code.lower(), code.upper()
    return [lo] if lo == hi else [lo, hi]


def _replace_last(p: str, old: str, new: str) -> str:
    '''
        Replace the LAST occurrence of `old` with `new` (the inner separator,
        not the leading slash).
    '''
    idx = p.rfind(old)
    return p if idx == -1 else p[:idx] + new + p[idx + len(old):]


def _enc_slash(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with encoded slashes.

        e.g. /foo/bar -> /foo%2fbar, /foo%2Fbar
    '''
    return [_replace_last(p, "/", c) for c in _both_cases("%2f")]


def _double_enc(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with double-encoded slashes and dots.

        e.g. /foo/bar -> /foo%252fbar, /foo%252Fbar
             /a.b     -> /a%252eb, /a%252Eb
    '''
    out = [_replace_last(p, "/", c) for c in _both_cases("%252f")]
    out += [p.replace(".", c) for c in _both_cases("%252e")]
    return out


def _dot_segments(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with dot segments.

        e.g. /foo/bar -> /foo/../bar, /foo/..%2fbar, /foo/..%2Fbar,
                         /foo/%2e%2ebar, /foo/..%252fbar
             /foo/bar -> /foo/bar/.., /foo/bar/.
    '''
    segs = [s for s in p.split("/") if s]
    out: list[str] = []
    if len(segs) > 1:
        inj = "/" + "/".join(segs[:-1] + ["..", segs[-1]])
        out.append(inj)
        for c in _both_cases("%2e"):
            out.append(inj.replace("..", c + c))
        for c in _both_cases("%2f"):
            out.append(inj.replace("/../", "/.." + c))
        for c in _both_cases("%252f"):
            out.append(inj.replace("/../", "/.." + c))
    out += [p + "/..", p + "/."]
    return out


def _semicolon(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with matrix parameters.

        e.g. /foo/bar -> /foo;x=1/bar, /foo/;/bar
    '''
    segs = p.split("/")
    if len(segs) < 2:
        return []
    s2 = list(segs)
    s2[1] = s2[1] + ";x=1"
    return ["/".join(s2), p.replace("/", "/;/", 1)]


def _backslash(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with backslashes.

        e.g. /foo/bar -> /foo\\bar, /foo%5cbar, /foo%5Cbar
    '''
    return [_replace_last(p, "/", "\\")] + [_replace_last(p, "/", c) for c in _both_cases("%5c")]


def _multi_slash(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with multiple slashes.

        e.g. /foo/bar -> /foo//bar, //foo/bar
    '''
    return [_replace_last(p, "/", "//"), "/" + p]


def _trailing(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with trailing slashes.

        e.g. /foo/bar -> /foo/bar/, /foo/bar/., /foo/bar%2f, /foo/bar%2F
    '''
    return [p + "/", p + "/."] + [p + c for c in _both_cases("%2f")]


def _suffix(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with suffix extensions.

        e.g. /foo/bar -> /foo/bar.json, /foo/bar.css, /foo/bar;.css, /foo/bar%00.css
    '''
    return [p + ".json", p + ".css", p + ";.css", p + "%00.css"]


def _whitespace(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with whitespace and control characters.

        e.g. /foo/bar -> /foo/bar%09, /foo/bar%20, /foo/bar%0a, /foo/bar%0A,
                         /foo/bar%0d, /foo/bar%0D, /foo/bar%00
    '''
    out: list[str] = []
    for code in ("%09", "%20", "%0a", "%0d", "%00"):
        out += [p + c for c in _both_cases(code)]
    return out


def _overlong_utf8(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with overlong UTF-8 encoding of a slash.

        e.g. /foo/bar -> /foo%c0%afbar, /foo%C0%AFbar, /foo%e0%80%afbar, /foo%E0%80%AFbar
    '''
    out: list[str] = []
    for code in ("%c0%af", "%e0%80%af"):
        out += [_replace_last(p, "/", c) for c in _both_cases(code)]
    return out


def _case(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with case variations.

        e.g. /foo/bar -> /FOO/BAR, /FOO/bar
    '''
    variants = [p.upper()]
    segs = p.split("/")
    for i, s in enumerate(segs):
        if s:
            s2 = list(segs)
            s2[i] = s.upper()
            variants.append("/".join(s2))
            break
    return variants


def _query_fragment(p: str, ctx: MutationContext) -> list[str]:
    '''
        Generate variants of a path with query and fragment components.
        The traversal target comes from ctx.injection_target, not a literal.

        e.g. /foo/bar (target /admin/secret) ->
             /foo/bar?/../admin/secret, /foo/bar#/../admin/secret
    '''
    t = ctx.injection_target.lstrip("/")
    return [p + "?/../" + t, p + "#/../" + t]


_GENERATORS: dict[str, Callable[[str, MutationContext], list[str]]] = {
    "encoded-slash": _enc_slash,
    "double-encoding": _double_enc,
    "dot-segment": _dot_segments,
    "matrix-semicolon": _semicolon,
    "backslash": _backslash,
    "multi-slash": _multi_slash,
    "trailing": _trailing,
    "suffix-extension": _suffix,
    "whitespace-control": _whitespace,
    "overlong-utf8": _overlong_utf8,
    "case": _case,
    "query-fragment": _query_fragment,
}


def generate(base_paths: list[str], techniques: list[str] | None = None,
             ctx: MutationContext | None = None, max_depth: int = 1) -> Iterator[Mutation]:
    '''
        Generate mutations for each base path and technique.

        If techniques is None, all techniques are used.
        max_depth > 1 also yields COMBINATIONS: a technique applied to the output
        of another (depth 2 = pairs, etc.). All variants are de-duplicated per
        base path; immediate repeats of the same technique are skipped.
    '''
    ctx = ctx or MutationContext()
    techs = techniques or list(_GENERATORS)

    for base in base_paths:
        seen: set[str] = {base}
        yield Mutation("identity", "as-is", base, base)

        # depth 1: single techniques
        level: list[tuple[tuple[str, ...], str]] = []
        for tech in techs:
            for i, variant in enumerate(_GENERATORS[tech](base, ctx)):
                if variant and variant not in seen:
                    seen.add(variant)
                    yield Mutation(tech, f"{tech}#{i}", variant, base)
                    level.append(((tech,), variant))

        # depth >= 2: compositions
        for _ in range(2, max_depth + 1):
            nxt: list[tuple[tuple[str, ...], str]] = []
            for chain, var in level:
                for tech in techs:
                    if tech == chain[-1]:
                        continue
                    for variant in _GENERATORS[tech](var, ctx):
                        if variant and variant not in seen:
                            seen.add(variant)
                            combo = chain + (tech,)
                            name = "combo:" + "+".join(combo)
                            yield Mutation(name, name, variant, base)
                            nxt.append((combo, variant))
            level = nxt


def list_techniques() -> list[str]:
    '''
        List all available mutation techniques.
    '''
    return list(_GENERATORS)
