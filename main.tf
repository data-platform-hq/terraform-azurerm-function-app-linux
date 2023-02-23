resource "azurerm_application_insights" "this" {
  count               = var.enable_appinsights ? 1 : 0
  name                = "fn-${var.project}-${var.env}-${var.location}-${var.name}"
  location            = var.location
  resource_group_name = var.resource_group
  application_type    = var.application_type
  workspace_id        = var.analytics_workspace_id
  tags                = var.tags
}

data "azurerm_monitor_diagnostic_categories" "this" {
  count       = var.enable_diagnostic_setting ? 1 : 0
  resource_id = azurerm_linux_function_app.this.id
}

resource "azurerm_monitor_diagnostic_setting" "this" {
  count                          = var.enable_diagnostic_setting ? 1 : 0
  name                           = "fn-${var.project}-${var.env}-${var.location}-${var.name}"
  target_resource_id             = azurerm_linux_function_app.this.id
  log_analytics_workspace_id     = var.analytics_workspace_id
  log_analytics_destination_type = var.analytics_destination_type

  dynamic "enabled_log" {
    for_each = data.azurerm_monitor_diagnostic_categories.this[0].log_category_types
    content {
      category = enabled_log.value
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.this[0].metrics
    content {
      category = metric.value
    }
  }
  lifecycle {
    ignore_changes = [log_analytics_destination_type] # TODO remove when issue is fixed: https://github.com/Azure/azure-rest-api-specs/issues/9281
  }
}

locals {
  app_settings = {
    WEBSITES_ENABLE_APP_SERVICE_STORAGE = "true"
    WEBSITE_ENABLE_SYNC_UPDATE_SITE     = "true"
    JAVA_OPTS                           = "-Dlog4j2.formatMsgNoLookups=true"
    LOG4J_FORMAT_MSG_NO_LOOKUPS         = "true"
    WEBSITE_USE_PLACEHOLDER             = "0"
    AZURE_LOG_LEVEL                     = "info"
    AzureWebJobsDisableHomepage         = "true"
    AzureFunctionsWebHost__hostid       = substr("fn-${var.project}-${var.env}-${var.location}-${var.name}", -32, -1)
  }
  application_stack_struct = {
    dotnet_version              = null
    use_dotnet_isolated_runtime = null
    java_version                = null
    node_version                = null
    python_version              = null
    powershell_core_version     = null
    use_custom_runtime          = null
  }
  application_stack = merge(local.application_stack_struct, var.application_stack)
}

resource "azurerm_linux_function_app" "this" {
  name                          = "fn-${var.project}-${var.env}-${var.location}-${var.name}"
  location                      = var.location
  resource_group_name           = var.resource_group
  storage_account_name          = var.log_storage_name
  service_plan_id               = var.service_plan_id
  storage_uses_managed_identity = true
  https_only                    = true
  enabled                       = true
  builtin_logging_enabled       = false
  functions_extension_version   = "~4"
  tags                          = var.tags
  app_settings                  = merge(local.app_settings, var.app_settings)
  identity {
    type         = var.identity_ids == null ? "SystemAssigned" : "SystemAssigned, UserAssigned"
    identity_ids = var.identity_ids
  }
  site_config {
    application_insights_connection_string = var.enable_appinsights ? azurerm_application_insights.this[0].connection_string : null
    application_insights_key               = var.enable_appinsights ? azurerm_application_insights.this[0].instrumentation_key : null
    always_on                              = true
    ftps_state                             = "Disabled"
    http2_enabled                          = true
    websockets_enabled                     = false
    use_32_bit_worker                      = false
    ip_restriction                         = var.ip_restriction
    scm_ip_restriction                     = var.ip_restriction
    application_stack {
      dotnet_version              = local.application_stack.dotnet_version
      use_dotnet_isolated_runtime = local.application_stack.use_dotnet_isolated_runtime
      java_version                = local.application_stack.java_version
      node_version                = local.application_stack.node_version
      python_version              = local.application_stack.python_version
      powershell_core_version     = local.application_stack.powershell_core_version
      use_custom_runtime          = local.application_stack.use_custom_runtime
    }
  }
  lifecycle {
    ignore_changes = [
      tags["hidden-link: /app-insights-conn-string"],
      tags["hidden-link: /app-insights-instrumentation-key"],
      tags["hidden-link: /app-insights-resource-id"],
      virtual_network_subnet_id
    ]
  }
}

# TODO: deprecated
resource "azurerm_role_assignment" "storage" {
  for_each             = { for permision in var.azure_rbac : "${permision.scope}-${permision.role}" => permision }
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = azurerm_linux_function_app.this.identity[0].principal_id
}

resource "azurerm_app_service_virtual_network_swift_connection" "this" {
  count          = var.use_private_net ? 1 : 0
  app_service_id = azurerm_linux_function_app.this.id
  subnet_id      = var.subnet_id
}

# Set of permissions based on documentation:
# https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference
resource "azurerm_role_assignment" "log_storage_account_contributor" {
  count                = var.log_storage_id == null ? 0 : 1
  scope                = var.log_storage_id
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_linux_function_app.this.identity[0].principal_id
}

resource "azurerm_role_assignment" "log_storage_account_blob_data_owner" {
  count                = var.log_storage_id == null ? 0 : 1
  scope                = var.log_storage_id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = azurerm_linux_function_app.this.identity[0].principal_id
}

resource "azurerm_role_assignment" "log_storage_account_queue_data_contributor" {
  count                = var.log_storage_id == null ? 0 : 1
  scope                = var.log_storage_id
  role_definition_name = "Storage Queue Data Contributor"
  principal_id         = azurerm_linux_function_app.this.identity[0].principal_id
}

resource "azurerm_role_assignment" "this" {
  for_each             = { for permision in var.azure_rbac : "${permision.key}-${permision.role}" => permision }
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = each.value.principal_id
}


data "azurerm_function_app_host_keys" "this" {
  count               = var.use_private_net ? 0 : 1
  depends_on          = [azurerm_linux_function_app.this]
  name                = azurerm_linux_function_app.this.name
  resource_group_name = var.resource_group
}

data "azurerm_function_app_host_keys" "this_vnet" {
  count               = var.use_private_net ? 1 : 0
  depends_on          = [azurerm_linux_function_app.this, azurerm_app_service_virtual_network_swift_connection.this[0]]
  name                = azurerm_linux_function_app.this.name
  resource_group_name = var.resource_group
}
