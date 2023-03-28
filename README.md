# Azure Linux Function App Terraform module
Terraform module for creation Azure Linux Function App

## Usage

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | >= 3.40.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 3.24.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_app_service_virtual_network_swift_connection.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service_virtual_network_swift_connection) | resource |
| [azurerm_application_insights.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_insights) | resource |
| [azurerm_key_vault_access_policy.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_access_policy) | resource |
| [azurerm_linux_function_app.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_function_app) | resource |
| [azurerm_monitor_diagnostic_setting.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |
| [azurerm_role_assignment.log_storage_account_blob_data_owner](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.log_storage_account_contributor](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.log_storage_account_queue_data_contributor](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_role_assignment.storage](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) | resource |
| [azurerm_function_app_host_keys.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/function_app_host_keys) | data source |
| [azurerm_function_app_host_keys.this_vnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/function_app_host_keys) | data source |
| [azurerm_monitor_diagnostic_categories.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/monitor_diagnostic_categories) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_analytics_destination_type"></a> [analytics\_destination\_type](#input\_analytics\_destination\_type) | Possible values are AzureDiagnostics and Dedicated. | `string` | `"Dedicated"` | no |
| <a name="input_analytics_workspace_id"></a> [analytics\_workspace\_id](#input\_analytics\_workspace\_id) | Resource ID of Log Analytics Workspace | `string` | `null` | no |
| <a name="input_app_settings"></a> [app\_settings](#input\_app\_settings) | Application setting | `map(string)` | `{}` | no |
| <a name="input_application_stack"></a> [application\_stack](#input\_application\_stack) | Application stack | `map(string)` | <pre>{<br>  "java_version": "11"<br>}</pre> | no |
| <a name="input_application_type"></a> [application\_type](#input\_application\_type) | Application type (java, python, etc) | `string` | `"java"` | no |
| <a name="input_azure_rbac"></a> [azure\_rbac](#input\_azure\_rbac) | Azure RBAC permision map (scope, role) | `list(map(string))` | `[]` | no |
| <a name="input_enable_appinsights"></a> [enable\_appinsights](#input\_enable\_appinsights) | Enable application insights | `bool` | `true` | no |
| <a name="input_enable_diagnostic_setting"></a> [enable\_diagnostic\_setting](#input\_enable\_diagnostic\_setting) | Enable diagnostic setting. var.analytics\_workspace\_id must be provided | `bool` | `false` | no |
| <a name="input_env"></a> [env](#input\_env) | Environment | `string` | n/a | yes |
| <a name="input_identity_ids"></a> [identity\_ids](#input\_identity\_ids) | List of user assigned identity IDs | `list(string)` | `null` | no |
| <a name="input_ip_restriction"></a> [ip\_restriction](#input\_ip\_restriction) | Firewall settings for the function app | <pre>list(object({<br>    name                      = string<br>    ip_address                = optional(string, null)<br>    service_tag               = optional(string, null)<br>    virtual_network_subnet_id = optional(string, null)<br>    priority                  = optional(string, "100")<br>    action                    = string<br>    headers = optional(list(object({<br>      x_azure_fdid      = optional(list(string), null)<br>      x_fd_health_probe = optional(list(string), null)<br>      x_forwarded_for   = optional(list(string), null)<br>      x_forwarded_host  = optional(list(string), null)<br>    })), [])<br>  }))</pre> | <pre>[<br>  {<br>    "action": "Allow",<br>    "name": "allow_azure",<br>    "service_tag": "AzureCloud"<br>  }<br>]</pre> | no |
| <a name="input_key_vault"></a> [key\_vault](#input\_key\_vault) | Configure Linux Function App to Key Vault | <pre>object({<br>    id                  = optional(string, null)<br>    key_permissions     = optional(list(string), null)<br>    secret_permissions  = optional(list(string), ["Get", "List"])<br>    storage_permissions = optional(list(string), null)<br>  })</pre> | `{}` | no |
| <a name="input_location"></a> [location](#input\_location) | Location | `string` | n/a | yes |
| <a name="input_log_storage_id"></a> [log\_storage\_id](#input\_log\_storage\_id) | Logs storage account ID (to set permissions on it) | `string` | `null` | no |
| <a name="input_log_storage_name"></a> [log\_storage\_name](#input\_log\_storage\_name) | Logs storage account name | `string` | n/a | yes |
| <a name="input_name"></a> [name](#input\_name) | Function index/name (like 007) | `string` | n/a | yes |
| <a name="input_project"></a> [project](#input\_project) | Project name | `string` | n/a | yes |
| <a name="input_resource_group"></a> [resource\_group](#input\_resource\_group) | Resource group name | `string` | n/a | yes |
| <a name="input_scm_ip_restriction"></a> [scm\_ip\_restriction](#input\_scm\_ip\_restriction) | Firewall settings for the function app | <pre>list(object({<br>    name                      = string<br>    ip_address                = optional(string, null)<br>    service_tag               = optional(string, null)<br>    virtual_network_subnet_id = optional(string, null)<br>    priority                  = optional(string, "100")<br>    action                    = string<br>    headers = optional(list(object({<br>      x_azure_fdid      = optional(list(string), null)<br>      x_fd_health_probe = optional(list(string), null)<br>      x_forwarded_for   = optional(list(string), null)<br>      x_forwarded_host  = optional(list(string), null)<br>    })), [])<br>  }))</pre> | <pre>[<br>  {<br>    "action": "Allow",<br>    "name": "allow_azure",<br>    "service_tag": "AzureCloud"<br>  }<br>]</pre> | no |
| <a name="input_service_plan_id"></a> [service\_plan\_id](#input\_service\_plan\_id) | App Service plan ID | `string` | n/a | yes |
| <a name="input_subnet_id"></a> [subnet\_id](#input\_subnet\_id) | Subnet ID for the function app | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags | `map(string)` | n/a | yes |
| <a name="input_use_private_net"></a> [use\_private\_net](#input\_use\_private\_net) | Use private network injection | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_id"></a> [id](#output\_id) | Function app ID |
| <a name="output_identity"></a> [identity](#output\_identity) | Function app Managed Identity |
| <a name="output_outbound_ip_address_list"></a> [outbound\_ip\_address\_list](#output\_outbound\_ip\_address\_list) | Function app outbound IP address list |
| <a name="output_primary_key"></a> [primary\_key](#output\_primary\_key) | Function app primary key |
<!-- END_TF_DOCS -->

## License

Apache 2 Licensed. For more information please see [LICENSE](https://github.com/data-platform-hq/terraform-azurerm-function-app-linux/tree/main/LICENSE)
