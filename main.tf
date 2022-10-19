resource "azurerm_application_insights" "this" {
  name                = "fn-${var.project}-${var.env}-${var.location}-${var.name}"
  location            = var.location
  resource_group_name = var.resource_group
  application_type    = var.application_type
  tags                = var.tags
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
    AzureFunctionsWebHost__hostid       = substr(azurerm_application_insights.this.name, -32, -1)
  }
}

resource "azurerm_linux_function_app" "this" {
  depends_on                    = [azurerm_application_insights.this]
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
    type = "SystemAssigned"
  }
  site_config {
    application_insights_connection_string = azurerm_application_insights.this.connection_string
    application_insights_key               = azurerm_application_insights.this.instrumentation_key
    always_on                              = true
    ftps_state                             = "Disabled"
    http2_enabled                          = true
    websockets_enabled                     = false
    use_32_bit_worker                      = false
    ip_restriction                         = var.ip_restriction
    scm_ip_restriction                     = var.ip_restriction
    application_stack {
      java_version = var.java_version
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

data "azurerm_function_app_host_keys" "this" {
  depends_on          = [azurerm_linux_function_app.this]
  name                = azurerm_linux_function_app.this.name
  resource_group_name = var.resource_group
}