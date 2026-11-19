"""
    Oracle - anomaly detection and classification logic.

    Given one response (edge headers + backend diagnostic JSON), decides whether edge
    and backend disagreed about the request, and classify how based on the rules:

    R1 - authorization bypass
    R2 - edge and backend saw a different path (e.g. edge normalized the path, backend did not)
    R4 - backend matched an unexpected (admin) route
    R5 - normalizing redirect (e.g. Go net/http cleanPath)

"""

# IMPORTS
from __future__ import annotations
import json
from dataclasses import dataclass

from .transport import RawResponse

# Severity ranking for findings, used to determine the "top" finding in a verdict.
_SEVERITY = {"critical": 3, "high": 2, "info": 1}


@dataclass
class Finding:
    '''
        A single finding of a divergence between edge and backend.
    '''
    rule: str # R1 - R5
    severity: str # critical | high | info
    kind: str # kind of divergence (authz-bypass, path-divergence, route-divergence, normalizing-redirect)
    detail: str # human-readable description


@dataclass
class Verdict:
    '''
        The final verdict on whether the edge and backend disagreed about the request.
    '''

    divergent: bool
    findings: list[Finding]
    edge_decision: str
    edge_path: str
    backend_json: dict | None
    http_status: int

    @property
    def summary(self) -> str:
        '''
            Summary of the verdict.
        '''

        if not self.divergent:
            return "AGREEMENT"
        
        top = max(self.findings, key=_severity_rank)
        
        return f"DIVERGENCE [{top.rule}/{top.severity}]"


def _severity_rank(f: Finding) -> int:
    return _SEVERITY.get(f.severity, 0)


def _normalize_path(path: str) -> str:
    '''
        Normalize a path by removing "." and ".." segments.
        It is used to compare edge and backend paths for divergence.
    '''

    parts: list[str] = []
    
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    
    return "/" + "/".join(parts)


def evaluate_response(
            resp: RawResponse, 
            base_path: str, 
            secret_marker: str,
            protected_prefix: str = "/admin"
        ) -> Verdict:
    '''
        Evaluate a response from the edge and backend, and determine if there is a divergence.
        Returns a Verdict object with the findings.
    '''

    edge_decision = resp.header("x-edge-decision", "?")
    edge_path = resp.header("x-edge-path", "?")

    # Attempt to parse the backend JSON, if present.
    backend: dict | None = None
    if "application/json" in resp.header("content-type", "") or resp.text.strip().startswith("{"):
        try:
            backend = json.loads(resp.text)
        except (ValueError, json.JSONDecodeError):
            backend = None


    findings: list[Finding] = []

    base_is_protected = (base_path == protected_prefix) or base_path.startswith(protected_prefix + "/")
    secret_leaked = bool(secret_marker) and (secret_marker in resp.text)

    # R1 - authorization bypass
    if base_is_protected:
        backend_routed_admin = bool(backend and backend.get("is_admin_routed"))

        if secret_leaked or (edge_decision != "deny" and backend_routed_admin and resp.res_status == 200):
            finding = Finding(
                "R1", 
                "critical", 
                "authz-bypass",
                f"edge_decision={edge_decision} status={resp.res_status} secret_leaked={secret_leaked}",
            )
            findings.append(finding)

    if backend is not None:
        backend_path = backend.get("path_as_routed")
        # R2 - edge and backend saw a different path
        if edge_path not in ("?", "") and backend_path and _normalize_path(edge_path) != _normalize_path(backend_path):
            finding = Finding(
                "R2", 
                "high", 
                "path-divergence",
                f"edge_path={edge_path} backend_path={backend_path}",
            )
            findings.append(finding)

        # R4 - backend matched an unexpected (admin) route for a non-protected base
        if backend.get("is_admin_routed") and not base_is_protected:
            finding = Finding(
                "R4", 
                "high", 
                "route-divergence",
                f"base={base_path} matched={backend.get('matched_route')}",
            )
            findings.append(finding)

    # R5 - normalizing redirect (e.g. Go net/http cleanPath)
    if resp.res_status in (301, 302, 307, 308):
        finding = Finding(
            "R5", 
            "info", 
            "normalizing-redirect",
            f"status={resp.res_status} location={resp.header('location')}",
        )
        findings.append(finding)


    return Verdict(
        divergent=bool(findings),
        findings=findings,
        edge_decision=edge_decision,
        edge_path=edge_path,
        backend_json=backend,
        http_status=resp.res_status,
    )
