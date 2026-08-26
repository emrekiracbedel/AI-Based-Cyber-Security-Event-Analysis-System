"""
Sigma-like signature engine: YAML rules with field predicates (eq, contains, regex).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from app.config import settings


class SigmaEngine:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules_path = rules_path or settings.sigma_rules_path
        self.rules: list[dict[str, Any]] = []
        self._compiled: list[tuple[dict[str, Any], list[tuple[dict[str, Any], Any]]]] = []
        self.load()

    def load(self, path: Path | None = None) -> int:
        p = path or self.rules_path
        self.rules = []
        self._compiled = []
        if p is None or not p.is_file():
            return 0
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw = data.get("rules") or []
        for r in raw:
            if not isinstance(r, dict) or "id" not in r:
                continue
            conds = r.get("conditions") or []
            compiled_conds = []
            for c in conds:
                if not isinstance(c, dict):
                    continue
                op = (c.get("op") or "eq").lower()
                field = c.get("field")
                value = c.get("value")
                if field is None or value is None:
                    continue
                if op == "regex":
                    try:
                        compiled_conds.append((c, re.compile(str(value))))
                    except re.error:
                        continue
                else:
                    compiled_conds.append((c, str(value)))
            self.rules.append(r)
            self._compiled.append((r, compiled_conds))
        return len(self.rules)

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Return list of matches: {id, title, level}."""
        matches: list[dict[str, Any]] = []
        for rule, compiled_conds in self._compiled:
            ok = True
            for c, payload in compiled_conds:
                field = c.get("field")
                op = (c.get("op") or "eq").lower()
                actual = event.get(field)
                if actual is None:
                    actual = ""
                text = actual if isinstance(actual, str) else str(actual)
                if op == "eq":
                    if text != payload:
                        ok = False
                        break
                elif op == "contains":
                    if str(payload).lower() not in text.lower():
                        ok = False
                        break
                elif op == "regex":
                    if not payload.search(text):
                        ok = False
                        break
                else:
                    ok = False
                    break
            if ok and compiled_conds:
                matches.append(
                    {
                        "id": rule["id"],
                        "title": rule.get("title", rule["id"]),
                        "level": (rule.get("level") or "medium").lower(),
                    }
                )
        return matches


_engine: SigmaEngine | None = None


def get_sigma_engine(path: Path | None = None) -> SigmaEngine:
    global _engine
    if _engine is None:
        _engine = SigmaEngine(path or settings.sigma_rules_path)
    elif path is not None:
        _engine.rules_path = path
        _engine.load(path)
    return _engine
