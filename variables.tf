variable "project" {
  type        = string
  description = "Project name"
}

variable "env" {
  type        = string
  description = "Environment"
}

variable "location" {
  type        = string
  description = "Location"
}

variable "tags" {
  type        = map(string)
  description = "Tags"
}

variable "resource_group" {
  type        = string
  description = "Resource group name"
}


variable "service_plan_id" {
  type        = string
  description = "App Service plan ID"
}

variable "log_storage_name" {
  type        = string
  description = "Logs storage account name"
}

variable "log_storage_id" {
  type        = string
  description = "Logs storage account ID (to set permissions on it)"
  default     = null
}

variable "name" {
  type        = string
  description = "Function index/name (like 007)"
}

variable "application_type" {
  type        = string
  description = "Application type (java, python, etc)"
  default     = "java"
}

variable "application_stack" {
  type        = map(string)
  description = "Application stack"
  default = {
    java_version = "11"
  }
}

variable "ip_restriction" {
  description = "Firewall settings for the function app"
  type = list(object({
    name                      = string
    ip_address                = string
    service_tag               = string
    virtual_network_subnet_id = string
    priority                  = string
    action                    = string
    headers = list(object({
      x_azure_fdid      = list(string)
      x_fd_health_probe = list(string)
      x_forwarded_for   = list(string)
      x_forwarded_host  = list(string)
    }))
  }))
  default = [
    {
      name                      = "allow_azure"
      ip_address                = null
      service_tag               = "AzureCloud"
      virtual_network_subnet_id = null
      priority                  = "100"
      action                    = "Allow"
      headers                   = null
    }
  ]
}

variable "app_settings" {
  type        = map(string)
  default     = {}
  description = "Application setting"
}

variable "azure_rbac" {
  type        = list(map(string))
  description = "Azure RBAC permision map (scope, role)"
  default     = []
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the function app"
  default     = null
}

variable "use_private_net" {
  type        = bool
  description = "Use private network injection"
  default     = false
}

variable "identity_ids" {
  type        = list(string)
  description = "List of user assigned identity IDs"
  default     = null
}

variable "enable_appinsights" {
  type        = bool
  description = "Enable application insights"
  default     = true
}

variable "analytics_workspace_id" {
  type        = string
  description = "Resource ID of Log Analytics Workspace"
  default     = null
}

variable "analytics_destination_type" {
  type        = string
  description = "Possible values are AzureDiagnostics and Dedicated."
  default     = "Dedicated"
}

variable "enable_diagnostic_setting" {
  type        = bool
  description = "Enable diagnostic setting. var.analytics_workspace_id must be provided"
  default     = false
}

variable "key_vault" {
  description = "Configure Linux Function App to Key Vault"
  type = object({
    id                  = optional(string, null)
    key_permissions     = optional(list(string), null)
    secret_permissions  = optional(list(string), ["Get", "List"])
    storage_permissions = optional(list(string), null)
  })
}
