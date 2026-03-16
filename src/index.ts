export { createMcpWorker } from "./worker.js";
export { checkAuth, fetchUserCredentials } from "./acl.js";
export type { AuthEnv, AuthCheckResult } from "./acl.js";
import {
  createTokenResolver,
  createWorkOSHandler,
  createOAuthState,
  bindStateToSession,
  validateOAuthState,
  OAuthError,
  getUpstreamAuthorizeUrl,
  fetchWorkOSAuthToken,
} from "./advanced.js";

/**
 * Escape hatches for services that need to bypass the standard `createMcpWorker()` path.
 * Most consumers should stick to `createMcpWorker()` and the exported types above.
 */
export const advanced = {
  createTokenResolver,
  createWorkOSHandler,
  createOAuthState,
  bindStateToSession,
  validateOAuthState,
  OAuthError,
  getUpstreamAuthorizeUrl,
  fetchWorkOSAuthToken,
} as const;

export type {
  McpAuthEnv,
  McpAgentProps,
  McpCredentials,
  McpKeyMeta,
  McpWorkerConfig,
  ResolvedAuth,
} from "./types.js";

export type { WorkOSAuthResult } from "./utils.js";
