export interface CheckRequest {
  email: string;
  service: string;
  tool: string;
}

export interface CheckResponse {
  allowed: boolean;
  reason: string;
}

export interface PolicyLine {
  ptype: string;
  v0: string;
  v1: string;
  v2: string;
  v3: string;
}
