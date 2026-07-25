import re
from typing import TypedDict


class SafetyReport(TypedDict):
    is_safe: bool
    warnings: list[str]


DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"rm\s+(-[^\s]*\s+)*-[^\s]*\s*/\s*$|rm\s+(-[^\s]*\s+)*/\s*$", re.I), "rm -rf / (recursive delete of root)"),
    (re.compile(r"rm\s+-[^\s]*r[^\s]*\s+/-|rm\s+-rf\s+/\s", re.I), "rm -rf / variant"),
    (re.compile(r"\bmkfs\b", re.I), "mkfs (filesystem format)"),
    (re.compile(r":\(\)\s*\{\s*:\|\:\s*&\s*\}\s*;", re.I), "fork bomb"),
    (re.compile(r"dd\s+if=.*\s+of=/dev/(sd|hd|nvme|vd)", re.I), "dd writing to block device"),
    (re.compile(r">\s*/dev/sd[a-z]", re.I), "redirect overwrite of block device"),
    (re.compile(r"\bshutdown\s+-h\s+now\b|\breboot\b|\binit\s+0\b", re.I), "system shutdown/reboot"),
    (re.compile(r"chmod\s+-R\s+777\s+/", re.I), "world-writable permissions on root tree"),
    (re.compile(r"curl\s+[^\|]+\|\s*(ba)?sh", re.I), "pipe curl to shell"),
    (re.compile(r"wget\s+[^\|]+\|\s*(ba)?sh", re.I), "pipe wget to shell"),
]


def inspect_script_safety(script_code: str) -> SafetyReport:
    warnings: list[str] = []
    normalized = script_code or ""

    for pattern, message in DESTRUCTIVE_PATTERNS:
        if pattern.search(normalized):
            warnings.append(message)

    return {
        "is_safe": len(warnings) == 0,
        "warnings": warnings,
    }
