# AzureServicePrincipalAccount PowerShell Module

#### Module version history
| Author | Date | Version | Comment |
|:--- | :---: | :---: | :---
Tao Yang | 06/10/2017 | 1.0.1 | Initial release
Tao Yang | 23/10/2017 | 1.1.0 | Added Get-AzureADToken function
Tao Yang | 31/10/2017 | 1.2.0 | Get-AzureADToken added support for user principals
Tao Yang | 20/11/2017 | 1.3.0 | Get-AzureADToken added support for interactive user logins (ideally for MFA-Enabled users)
Tao Yang | 21/11/2017 | 1.4.0 | Get-AzureADToken added support for passing in user name for interactive user logins (ideally for MFA-Enabled users)
Tao Yang | 04/02/2018 | 1.5.0 | Get-AzureADToken added support for certificate-based Azure AD Service Principals
Tao Yang | 18/04/2019 | 2.0.0 | Updated the module to use the new Az PowerShell module. **Do not use this version if you are still using AzureRM modules.**
Tao Yang | 07/04/2021 | 2.1.0 | Added Microsoft.IdentityModel.Clients.ActiveDirectory.dll to the module since the Az PowerShell module no longer uses it.

## Introduction
The **AzureServicePrincipalAccount** Powershell module is designed to simplify the Azure Sign-In process within the Azure Automation accounts using Azure AD Service Principals.

### Add-AzServicePrincipalAccount

By the default, the Azure AD Service Principal connection type provided by Azure Automation accounts only supports certificate-based Azure AD Service Principals. This module provides an additional connection type for key-based Service Principals:

![](images/connectiontype.png)

When you are using an Azure service principal connection defined in your automation account, no matter whether you use the built-in certificate-based connection, or the key-based connection defined in this module, you can simply use an unique command to sign-in to your Azure subscription:
~~~PowerShell
Add-AzServicePrincipalAccount -AzureServicePrincipalConnection $AzureSPConnection
~~~

#### Sample PowerShell Runbook
~~~PowerShell
[CmdletBinding()]
Param(
  [String]$ConnectioNName
)

$AzureSPConnection = Get-AutomationConnection -Name $ConnectioNName

If ($AzureSPConnection)
{
  $Login = Add-AzServicePrincipalAccount -AzureServicePrincipalConnection $AzureSPConnection
  $Login.Context
} else {
  Write-Error "Connection asset '$ConnectionName' does not exist in this Automation account."
}
~~~

### Get-AzureADToken

**Get-AzureADToken** is a generic function that provides a simplified way to generate Azure AD oAuth2 token for accessing various Azure resources. You access the help file in PowerShell:
~~~PowerShell
Get-help Get-AzureADToken -Full
~~~

It is a known issue that when executing a runbook on Azure runbook workers, you cannot use a credential-based security principal (including user principals and key-based service principals). When using a key-based Service Principal, an alternative is to use Azure Resource Manager REST API directly (instead of using AzureRM PowerShell modules). You can use Get-AzureADToken to generate appropriate oAuth token for the REST API calls. The Azure Resource Manager REST API is fully documented here: [https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-rest-api](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-rest-api)

>**Note:** this issue is documented here: [https://github.com/Azure/azure-powershell/issues/2067](https://github.com/Azure/azure-powershell/issues/2067) and here: [https://feedback.azure.com/forums/246290-automation/suggestions/16304161-add-azurermaccount-doesn-t-work-with-service-princ](https://feedback.azure.com/forums/246290-automation/suggestions/16304161-add-azurermaccount-doesn-t-work-with-service-princ)

