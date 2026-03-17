variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "zone_id" {
  description = "Cloudflare zone ID"
  type        = string
}

variable "domain" {
  description = "Root domain name"
  type        = string
}

variable "worker_script_name" {
  description = "Worker script name deployed by Wrangler"
  type        = string
  default     = "cassandra-auth"
}

variable "worker_subdomain" {
  description = "Public auth Worker subdomain"
  type        = string
  default     = "acl"
}
