import { Hono } from "hono";
import { pushMetrics, counter } from "cassandra-observability";
import { Enforcer } from "./enforcer";
import { POLICIES } from "./policy";
import type { CheckRequest } from "./types";

const app = new Hono<{ Bindings: Env }>();

// Enforcer is built once from baked-in YAML policy — no DB calls needed.
const enforcer = new Enforcer(POLICIES);

// ── Auth: shared secret OR CF Access service token ──

function requireAuth(c: { req: { header: (name: string) => string | undefined }; env: Env }): boolean {
  // Path 1: shared secret
  const secret = c.req.header("X-ACL-Secret");
  if (secret && secret === c.env.ACL_SECRET) return true;

  // Path 2: CF Access service token (for external callers through Cloudflare)
  const cfClientId = c.req.header("CF-Access-Client-Id");
  if (cfClientId && c.env.CF_ACCESS_CLIENT_ID && cfClientId === c.env.CF_ACCESS_CLIENT_ID) return true;

  return false;
}

// ── Metrics middleware ──

app.use("*", async (c, next) => {
  const start = Date.now();
  await next();
  c.executionCtx.waitUntil(
    pushMetrics(c.env, [
      counter("mcp_requests_total", 1, {
        service: "acl",
        status: String(c.res.status),
        path: new URL(c.req.url).pathname,
      }),
      counter("mcp_request_duration_ms_total", Date.now() - start, {
        service: "acl",
        path: new URL(c.req.url).pathname,
      }),
    ]),
  );
});

// ── Health check ──

app.get("/health", (c) => c.json({ ok: true }));

// ── POST /check — ACL enforcement ──

app.post("/check", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const body = await c.req.json<CheckRequest>();
  if (!body.email || !body.service || !body.tool) {
    return c.json({ error: "email, service, and tool are required" }, 400);
  }

  const result = enforcer.enforce(body.email, body.service, body.tool);
  return c.json(result);
});

// ── GET /policy — return current baked-in policy ──

app.get("/policy", (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);
  return c.json({ policies: POLICIES });
});

// ── POST /credentials/:email/:service — store per-user credentials ──

app.post("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const credentials = await c.req.json<Record<string, string>>();

  const key = `cred:${email}:${service}`;
  await c.env.ACL_CREDENTIALS.put(key, JSON.stringify(credentials));

  return c.json({ ok: true });
});

// ── GET /credentials/:email/:service — retrieve per-user credentials ──

app.get("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const key = `cred:${email}:${service}`;
  const value = await c.env.ACL_CREDENTIALS.get(key, "json");

  if (!value) return c.json({ credentials: null });
  return c.json({ credentials: value });
});

// ── POST /keys/validate — validate an MCP API key and return metadata ──

app.post("/keys/validate", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { key } = await c.req.json<{ key: string }>();
  if (!key) return c.json({ error: "key is required" }, 400);

  const raw = await c.env.MCP_KEYS.get(key);
  if (!raw) return c.json({ valid: false }, 404);

  let meta: Record<string, unknown>;
  try {
    meta = JSON.parse(raw);
  } catch {
    return c.json({ valid: false }, 500);
  }

  return c.json({
    valid: true,
    email: meta.created_by || meta.email,
    service: meta.service,
    credentials: meta.credentials || null,
  });
});

// ── DELETE /credentials/:email/:service — remove per-user credentials ──

app.delete("/credentials/:email/:service", async (c) => {
  if (!requireAuth(c)) return c.json({ error: "unauthorized" }, 401);

  const { email, service } = c.req.param();
  const key = `cred:${email}:${service}`;
  await c.env.ACL_CREDENTIALS.delete(key);

  return c.json({ ok: true });
});

export default app;
