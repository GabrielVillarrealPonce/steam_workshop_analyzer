"""Static analysis of script wallpapers (Web/Scene: JavaScript, Lua, HTML).

This is a pattern-based scanner, not a full AST parse -- the project ships no
JS/Lua parser dependency, so we scan source text with calibrated regexes and
say so plainly. The trade-off is deliberate: an AST would cut false positives
on commented-out code, but the finding severities are tuned so that a single
heuristic hit ESCALATES for human review rather than blocking outright
(swa.stage4_decision), which is the right failure mode for a heuristic.

Detections (design doc 6.1): dynamic code execution (eval/loadstring),
obfuscation (base64/hex/fromCharCode), sandbox-escape APIs (require, os.execute,
ffi), and network calls whose destination isn't in the author's declared
domain allowlist. Shared IOCs (undeclared URLs, Steam paths, wallets, LOLBins)
come from indicators.scan_common_iocs over the same text.
"""

from __future__ import annotations

import re

from ..models import FileType, Finding, Severity
from . import indicators
from .config import DEFAULT_CONFIG, StaticConfig

# Dynamic code execution.
_JS_DYNAMIC_RE = re.compile(
    r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*['\"]|"
    r"\bsetInterval\s*\(\s*['\"]",
)
_LUA_DYNAMIC_RE = re.compile(r"\bloadstring\s*\(|\bload\s*\(|\bdofile\s*\(")

# Network APIs (presence; the destination check is done separately).
_NET_API_RE = re.compile(
    r"\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\s*\(|\bimportScripts\s*\(|"
    r"navigator\.sendBeacon|\baxios\b|\$\.(?:ajax|get|post)\b|"
    r"\bsocket\.http\b|\bhttp\.request\b",
    re.IGNORECASE,
)

# Attempts to reach outside the CEF/scene sandbox.
_JS_SANDBOX_RE = re.compile(
    r"\brequire\s*\(|\bprocess\.(?:env|platform|binding|mainModule)|"
    r"\bchild_process\b|\bActiveXObject\b|\bWScript\b|\bshell\.run\b",
)
_LUA_SANDBOX_RE = re.compile(
    r"\bos\.execute\b|\bio\.popen\b|\bos\.getenv\b|\bos\.remove\b|"
    r"\bpackage\.loadlib\b|\brequire\s*\(\s*['\"]ffi['\"]|\bffi\.",
)

# Obfuscation heuristics.
_ATOB_RE = re.compile(r"\batob\s*\(|\bfromCharCode\b|\bunescape\s*\(")
_FROMCHARCODE_RE = re.compile(r"fromCharCode")
_HEXESC_RE = re.compile(r"\\x[0-9a-fA-F]{2}")

# HTML external resource references.
_HTML_RES_RE = re.compile(r"""(?:src|href)\s*=\s*['\"]([^'\"]+)['\"]""", re.IGNORECASE)


def _long_blob_re(min_len: int) -> re.Pattern[str]:
    return re.compile(r"""['"][A-Za-z0-9+/]{%d,}={0,2}['"]""" % min_len)


def analyze_script(
    text: str,
    name: str,
    filetype: FileType,
    allowed_domains: set[str],
    config: StaticConfig = DEFAULT_CONFIG,
) -> list[Finding]:
    """Scan script source (already decoded to str) for Stage 2 indicators."""
    findings: list[Finding] = list(
        indicators.scan_common_iocs(text, name, allowed_domains, config)
    )

    is_lua = filetype is FileType.LUA
    dynamic_re = _LUA_DYNAMIC_RE if is_lua else _JS_DYNAMIC_RE
    sandbox_re = _LUA_SANDBOX_RE if is_lua else _JS_SANDBOX_RE

    if dynamic_re.search(text):
        findings.append(
            Finding(
                code="dynamic_code_execution",
                severity=Severity.MEDIUM,
                message="dynamic code execution (eval/new Function/loadstring)",
                path=name,
            )
        )

    if sandbox_re.search(text):
        findings.append(
            Finding(
                code="sandbox_escape_api",
                severity=Severity.MEDIUM,
                message=(
                    "call to an API outside the browser/scene sandbox "
                    "(process/child_process/os.execute/ffi)"
                ),
                path=name,
            )
        )

    # Obfuscation: any one of several signals is enough for a single finding.
    obfuscated = bool(_long_blob_re(config.long_blob_len).search(text)) or bool(
        _ATOB_RE.search(text)
    )
    if not obfuscated and len(_FROMCHARCODE_RE.findall(text)) >= config.fromcharcode_threshold:
        obfuscated = True
    if not obfuscated and len(_HEXESC_RE.findall(text)) >= 40:
        obfuscated = True
    if obfuscated:
        findings.append(
            Finding(
                code="obfuscated_code",
                severity=Severity.MEDIUM,
                message="obfuscated strings (base64/hex/fromCharCode/atob)",
                path=name,
            )
        )

    # HTML: also treat external src/href resources as network destinations.
    if filetype is FileType.HTML:
        undeclared: list[str] = []
        for ref in _HTML_RES_RE.findall(text):
            host = indicators.host_of(ref)
            if host and not indicators.host_is_declared(host, allowed_domains):
                if host not in undeclared:
                    undeclared.append(host)
        # Same message shape as scan_common_iocs so an absolute href already
        # caught as a text URL collapses in dedup instead of double-scoring.
        already = {
            f.message for f in findings if f.code == "network_undeclared_domain"
        }
        for host in undeclared[: config.max_undeclared_host_findings]:
            msg = f"references domain '{host}' not declared in project.json"
            if msg not in already:
                already.add(msg)
                findings.append(
                    Finding(
                        code="network_undeclared_domain",
                        severity=Severity.MEDIUM,
                        message=msg,
                        path=name,
                    )
                )

    # A network call whose destination we could NOT resolve to a literal URL
    # (built at runtime) is worth noting, but only once and only when no
    # concrete undeclared host was already flagged for this file.
    if _NET_API_RE.search(text) and not any(
        f.code == "network_undeclared_domain" for f in findings
    ):
        findings.append(
            Finding(
                code="dynamic_network_destination",
                severity=Severity.LOW,
                message="network call whose destination is not a static URL literal",
                path=name,
            )
        )

    return findings
