output "primary_key" {
  value       = data.azurerm_function_app_host_keys.this.primary_key
  description = "Function app primary key"
}

output "id" {
  value       = azurerm_linux_function_app.this.id
  description = "Function app ID"
}

output "identity" {
  value       = azurerm_linux_function_app.this.identity.*
  description = "Function app Managed Identity"
}
