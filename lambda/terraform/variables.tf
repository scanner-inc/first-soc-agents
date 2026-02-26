variable "aws_region" {
  default = "us-west-2"
}

variable "aws_profile" {
  default = "dev-data-gen.admin"
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

variable "scanner_mcp_url" {
  type    = string
  default = ""
}

variable "scanner_mcp_api_key" {
  type      = string
  sensitive = true
  default   = ""
}

variable "model" {
  type    = string
  default = "claude-opus-4-6"
}
