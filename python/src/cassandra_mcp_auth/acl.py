"""Python port of the Casbin-compatible ACL enforcer from cassandra-auth."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(slots=True)
class PolicyLine:
    ptype: str  # "p" for policy, "g" for role grouping
    v0: str
    v1: str
    v2: str
    v3: str


@dataclass(slots=True)
class CheckResponse:
    allowed: bool
    reason: str


class Enforcer:
    """Lightweight Casbin-compatible enforcer. Mirrors cassandra-auth/worker/src/enforcer.ts."""

    def __init__(self, policies: list[PolicyLine]) -> None:
        self._policies: list[PolicyLine] = []
        self._role_links: dict[str, set[str]] = {}

        for line in policies:
            if line.ptype == "p":
                self._policies.append(line)
            elif line.ptype == "g":
                self._role_links.setdefault(line.v0, set()).add(line.v1)

    def _has_role(self, sub: str, role: str) -> bool:
        if sub == role:
            return True

        visited: set[str] = set()
        queue = [sub]

        # Domain-based role: user@example.com → domain:example.com
        if sub is None:
            return sub == role
        at_idx = sub.find("@")
        if at_idx != -1:
            queue.append(f"domain:{sub[at_idx + 1:]}")

        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)

            if current == role:
                return True

            roles = self._role_links.get(current)
            if roles:
                for r in roles:
                    if r == role:
                        return True
                    queue.append(r)

        return False

    def enforce(self, sub: str, svc: str, tool: str) -> CheckResponse:
        has_allow = False
        has_deny = False

        for p in self._policies:
            sub_match = p.v0 == "*" or self._has_role(sub, p.v0)
            svc_match = p.v1 == "*" or p.v1 == svc
            tool_match = p.v2 == "*" or p.v2 == tool

            if sub_match and svc_match and tool_match:
                if p.v3 == "allow":
                    has_allow = True
                if p.v3 == "deny":
                    has_deny = True

        # Effect: some(allow) && !some(deny)
        allowed = has_allow and not has_deny

        if not has_allow and not has_deny:
            reason = "no matching policy"
        elif has_deny:
            reason = "explicitly denied"
        else:
            reason = "allowed by policy"

        return CheckResponse(allowed=allowed, reason=reason)

    def allowed_tools(self, sub: str, svc: str, all_tools: list[str]) -> list[str]:
        """Return the subset of tools that the subject is allowed to use."""
        return [t for t in all_tools if self.enforce(sub, svc, t).allowed]


# ---------------------------------------------------------------------------
# YAML → PolicyLine parser (mirrors cassandra-auth/worker/src/policy.ts)
# ---------------------------------------------------------------------------


def _build_policies(config: dict) -> list[PolicyLine]:
    policies: list[PolicyLine] = []

    def add(ptype: str, v0: str, v1: str, v2: str, v3: str) -> None:
        policies.append(PolicyLine(ptype=ptype, v0=v0, v1=v1, v2=v2, v3=v3))

    # Groups
    for group, gdef in (config.get("groups") or {}).items():
        for svc, svc_def in (gdef.get("services") or {}).items():
            if svc_def.get("access") == "allow":
                add("p", group, svc, "*", "allow")
            tools = svc_def.get("tools") or {}
            for tool in tools.get("deny") or []:
                add("p", group, svc, tool, "deny")
            for tool in tools.get("allow") or []:
                add("p", group, svc, tool, "allow")

    # Users
    for email, user in (config.get("users") or {}).items():
        if user.get("role") == "admin":
            add("p", email, "*", "*", "allow")
        for grp in user.get("groups") or []:
            add("g", email, grp, "", "")

    # Domains
    for domain, ddef in (config.get("domains") or {}).items():
        for grp in ddef.get("groups") or []:
            add("g", f"domain:{domain}", grp, "", "")

    return policies


def load_enforcer(acl_yaml_path: str | Path) -> Enforcer:
    """Load ACL policy from a YAML file and return a configured Enforcer."""
    path = Path(acl_yaml_path)
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    policies = _build_policies(config)
    return Enforcer(policies)
