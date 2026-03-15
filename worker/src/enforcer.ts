import type { PolicyLine, CheckResponse } from "./types";

/**
 * Lightweight Casbin-compatible enforcer that runs in a CF Worker.
 * Implements the RBAC model logic directly — no Node.js deps needed.
 */
export class Enforcer {
  private policies: PolicyLine[] = [];
  private roleLinks: Map<string, Set<string>> = new Map();

  constructor(policies: PolicyLine[]) {
    for (const line of policies) {
      if (line.ptype === "p") {
        this.policies.push(line);
      } else if (line.ptype === "g") {
        const subs = this.roleLinks.get(line.v0) ?? new Set();
        subs.add(line.v1);
        this.roleLinks.set(line.v0, subs);
      }
    }
  }

  /**
   * Check if sub has role (direct or transitive).
   * Also supports domain-based role assignment: if sub is an email,
   * check if domain:example.com has the role.
   */
  private hasRole(sub: string, role: string): boolean {
    if (sub === role) return true;

    const visited = new Set<string>();
    const queue = [sub];

    // Also check domain-based role
    const atIdx = sub.indexOf("@");
    if (atIdx !== -1) {
      queue.push(`domain:${sub.slice(atIdx + 1)}`);
    }

    while (queue.length > 0) {
      const current = queue.pop()!;
      if (visited.has(current)) continue;
      visited.add(current);

      if (current === role) return true;

      const roles = this.roleLinks.get(current);
      if (roles) {
        for (const r of roles) {
          if (r === role) return true;
          queue.push(r);
        }
      }
    }

    return false;
  }

  enforce(sub: string, svc: string, tool: string): CheckResponse {
    let hasAllow = false;
    let hasDeny = false;

    for (const p of this.policies) {
      const subMatch = p.v0 === "*" || this.hasRole(sub, p.v0);
      const svcMatch = p.v1 === "*" || p.v1 === svc;
      const toolMatch = p.v2 === "*" || p.v2 === tool;

      if (subMatch && svcMatch && toolMatch) {
        if (p.v3 === "allow") hasAllow = true;
        if (p.v3 === "deny") hasDeny = true;
      }
    }

    // Effect: some(allow) && !some(deny)
    const allowed = hasAllow && !hasDeny;

    let reason: string;
    if (!hasAllow && !hasDeny) {
      reason = "no matching policy";
    } else if (hasDeny) {
      reason = "explicitly denied";
    } else {
      reason = "allowed by policy";
    }

    return { allowed, reason };
  }
}
