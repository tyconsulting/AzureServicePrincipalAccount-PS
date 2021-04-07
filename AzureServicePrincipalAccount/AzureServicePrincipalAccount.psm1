# .EXTERNALHELP AzureServicePrincipalAccount.psm1-Help.xml
Function Add-AzServicePrincipalAccount {
  [OutputType('PSAzureProfile')]
  [CmdletBinding()]
  Param(
    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $true, HelpMessage = "Please specify the Azure Automation 'AzureServicePrincipal' or 'Key Based AzureServicePrincipal' connection object")]
    [Object]$AzureServicePrincipalConnection,

    [Parameter(ParameterSetName = 'BySPKey', Mandatory = $true, HelpMessage = 'Please specify the Azure AD Application ID')]
    [Parameter(ParameterSetName = 'BySPCert', Mandatory = $true, HelpMessage = 'Please specify the Azure AD Application ID')]
    [Alias('AppId')]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [string]$ApplicationId,

    [Parameter(ParameterSetName = 'BySPKey', Mandatory = $false, HelpMessage = 'Please specify the Azure AD tenant ID')]
    [Parameter(ParameterSetName = 'BySPCert', Mandatory = $false, HelpMessage = 'Please specify the Azure AD tenant ID')]
    [Alias('Tenant')]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'BySPKey', Mandatory = $false, HelpMessage = 'Please specify the Azure subscription ID')]
    [Parameter(ParameterSetName = 'BySPCert', Mandatory = $false, HelpMessage = 'Please specify the Azure subscription ID')]
    [Alias('Subscription')]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [string]$SubscriptionId,

    [Parameter(ParameterSetName = 'BySPKey', Mandatory = $false, HelpMessage = 'Please specify the Azure environment')]
    [Parameter(ParameterSetName = 'BySPCert', Mandatory = $false, HelpMessage = 'Please specify the Azure environment')]
    [Alias('env')]
    [ValidateNotNullOrEmpty()]
    [string]$Environment = 'AzureCloud',

    [Parameter(ParameterSetName = 'BySPKey', Mandatory = $true, HelpMessage = 'Please specify the Azure AD Application Service Principal Key')]
    [Alias('Password')]
    [ValidateNotNullOrEmpty()]
    [SecureString]$ServicePrincipalKey,

    [Parameter(ParameterSetName = 'BySPCert', Mandatory = $true, HelpMessage = 'Please specify the Azure AD Application Service Principal certificate thumbprint')]
    [Alias('Thumbprint')]
    [ValidateNotNullOrEmpty()]
    [string]$CertThumbprint
  )

  #Determine connection type

  If ($PSCmdlet.ParameterSetName -eq 'BySPConnection') {
    Write-Verbose "A connection object is specified. Determining the connection type..."
    $bvalidConnectionObject = $false
    if ($AzureServicePrincipalConnection.ContainsKey('Applicationid') -and $AzureServicePrincipalConnection.ContainsKey('TenantId') -and $AzureServicePrincipalConnection.ContainsKey('SubscriptionId')) {
      if ($AzureServicePrincipalConnection.ContainsKey('ServicePrincipalKey')) {
        $ConnectionType = "ByKey"
        $Applicationid = $AzureServicePrincipalConnection.ApplicationId
        $SPKey = $AzureServicePrincipalConnection.ServicePrincipalKey
        if ($SPkey -is [string]) {
          #Convert it to securestring
          $ServicePrincipalKey = New-Object System.Security.SecureString
          For ($i = 0; $i -lt $SPkey.length; $i++) {
            $char = $SPkey.Substring($i, 1)
            $ServicePrincipalKey.AppendChar($char)
          }
        }
        else {
          $ServicePrincipalKey = $SPKey
        }
        $TenantId = $AzureServicePrincipalConnection.TenantId
        $SubscriptionId = $AzureServicePrincipalConnection.SubscriptionId
        $bvalidConnectionObject = $true
      }
      elseif ($AzureServicePrincipalConnection.ContainsKey('CertificateThumbprint')) {
        $ConnectionType = "ByCert"
        $Applicationid = $AzureServicePrincipalConnection.ApplicationId
        $CertThumbprint = $AzureServicePrincipalConnection.CertificateThumbprint
        $TenantId = $AzureServicePrincipalConnection.TenantId
        $SubscriptionId = $AzureServicePrincipalConnection.SubscriptionId
        $bvalidConnectionObject = $true
      }
    }

    if (!$bvalidConnectionObject) {
      Write-Error "The connection object is invalid. please ensure the connection object type is either 'AzureServicePrincipal' or 'AzureServicePrincipal-KeyBased'."
      Exit -1
    }
  }
  elseif ($PSCmdlet.ParameterSetName -eq 'BySPKey') {
    $ConnectionType = "ByKey"
  }
  else {
    $ConnectionType = "ByCert"
  }

  #Login to Azure
  If ($ConnectionType -eq 'ByKey') {
    Write-Verbose "Login using an Azure AD service principal with key (password)"
    $Cred = New-Object System.Management.Automation.PSCredential($ApplicationId, $ServicePrincipalKey)
    $Login = Connect-AzAccount -ServicePrincipal -Credential $Cred -SubscriptionId $SubscriptionId -TenantId $TenantId -Environment $Environment
  }
  else {
    Write-Verbose "Login using an Azure AD service principal with certificate"
    $Login = Connect-AzAccount -ServicePrincipal -CertificateThumbprint $CertThumbprint -ApplicationId $ApplicationId -TenantId $TenantId -SubscriptionId $SubscriptionId -Environment $Environment
  }

  $Login
}

# .EXTERNALHELP AzureServicePrincipalAccount.psm1-Help.xml
Function Get-AzureADToken {
  [CmdletBinding()]
  [OutputType([string])]
  PARAM (
    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $true)]
    [Alias('Con', 'Connection')]
    [Object]$AzureServicePrincipalConnection,

    [Parameter(ParameterSetName = 'ByCred', Mandatory = $true)]
    [Parameter(ParameterSetName = 'UserInteractive', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [Alias('tID')]
    [String]$TenantID,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [String]$ApplicationId,

    [Parameter(ParameterSetName = 'ByCred', Mandatory = $true, HelpMessage = 'Please specify the Azure AD credential')]
    [Alias('cred')]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$Credential,

    [Parameter(ParameterSetName = 'UserInteractive', Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true, HelpMessage = 'Please specify the pfx Certificate file path')]
    [ValidateScript( { test-path $_ })]
    [string]$CertFilePath,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true, HelpMessage = 'Please specify the pfx Certificate file password')]
    [ValidateNotNullOrEmpty()]
    [SecureString]$CertFilePassword,

    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true, HelpMessage = "Please specify the Thumbprint of the certificate located in 'Cert:\LocalMachine\My' cert store")]
    [ValidateScript( { test-path "Cert:\LocalMachine\My\$_" })]
    [string]$CertThumbprint,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCred', Mandatory = $false)]
    [Parameter(ParameterSetName = 'UserInteractive', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$OAuthURI,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCred', Mandatory = $false)]
    [Parameter(ParameterSetName = 'UserInteractive', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$ResourceURI = 'https://management.azure.com/'
  )

  #URI to get oAuth Access Token
  If ($PSCmdlet.ParameterSetName -eq 'BySPConnection') {
    $TenantId = $AzureServicePrincipalConnection.TenantId
  }
  If (!$PSBoundParameters.ContainsKey('oAuthURI')) {
    $oAuthURI = "https://login.microsoftonline.com/$TenantId"
  }

  #Request token
  If ($PSCmdlet.ParameterSetName -eq 'BySPConnection') {
    if ($AzureServicePrincipalConnection.ContainsKey('Applicationid') -and $AzureServicePrincipalConnection.ContainsKey('TenantId') -and $AzureServicePrincipalConnection.ContainsKey('SubscriptionId')) {
      if ($AzureServicePrincipalConnection.ContainsKey('ServicePrincipalKey')) {

        #add /oauth2/token to the end of URI since this function not using the DLL to generate token
        if ($OAuthURI -ieq "https://login.microsoftonline.com/$TenantId") {
          $OAuthURI = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        }
        $token = Get-AzureADTokenForServicePrincipal -AzureServicePrincipalConnection $AzureServicePrincipalConnection -OAuthURI $OAuthURI -ResourceURI $ResourceURI
      }
      elseif ($AzureServicePrincipalConnection.ContainsKey('CertificateThumbprint')) {
        $token = Get-AzureADTokenForCertServicePrincipal -AzureServicePrincipalConnection $AzureServicePrincipalConnection -OAuthURI $OAuthURI -ResourceURI $ResourceURI
      }
    }
    else {
      Write-Error "The connection object is invalid. please ensure the connection object type must be either 'Key Based AzureServicePrincipal' or 'AzureServicePrincipal'."
      Exit -1
    }

  }
  elseif ($PSCmdlet.ParameterSetName -eq 'ByCred') {
    $ClientId = $Credential.UserName
    #Check if an Azure Application service principal is used
    try {
      [System.Guid]::Parse($ClientId) | Out-Null
      $bIsSP = $true
    }
    catch {
      $bIsSP = $false
    }

    if ($bIsSP) {
      #add /oauth2/token to the end of URI since this function not using the DLL to generate token
      if ($OAuthURI -ieq "https://login.microsoftonline.com/$TenantId") {
        $OAuthURI = "https://login.microsoftonline.com/$TenantId/oauth2/token"
      }
      $Token = Get-AzureADTokenForServicePrincipal -TenantID $TenantID -Credential $Credential -OAuthURI $OAuthURI -ResourceURI $ResourceURI
    }
    else {
      $Token = Get-AzureADTokenForUser -TenantID $TenantID -Credential $Credential -OAuthURI $OAuthURI -ResourceURI $ResourceURI
    }
  }
  elseif ($PSCmdlet.ParameterSetName -eq 'ByCertFile') {
    $Token = Get-AzureADTokenForCertServicePrincipal -TenantID $TenantID -ApplicationId $ApplicationId -CertFilePath $CertFilePath -CertFilePassword $CertFilePassword -OAuthURI $OAuthURI -ResourceURI $ResourceURI
  }
  elseif ($PSCmdlet.ParameterSetName -eq 'ByCertThumbprint') {
    $Token = Get-AzureADTokenForCertServicePrincipal -TenantID $TenantID -ApplicationId $ApplicationId -CertThumbprint $CertThumbprint -OAuthURI $OAuthURI -ResourceURI $ResourceURI
  }
  else {
    #Getting an token for user principal by interactive logon - support for MFA scenario
    $InteractiveParam = @{
      'TenantID'    = $TenantID
      'OAuthURI'    = $OAuthURI
      'ResourceURI' = $ResourceURI
    }
    if ($PSBoundParameters.ContainsKey('UserName')) {
      $InteractiveParam.Add('UserName', $UserName)
    }
    $Token = Get-AzureADTokenForUserInteractive @InteractiveParam
  }

  $token
}

Function Get-AzureADTokenForServicePrincipal {
  [CmdletBinding()]
  [OutputType([string])]
  PARAM (
    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $true)]
    [Alias('Con', 'Connection')]
    [Object]$AzureServicePrincipalConnection,

    [Parameter(ParameterSetName = 'ByCred', Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [Alias('tID')]
    [String]$TenantID,

    [Parameter(ParameterSetName = 'ByCred', Mandatory = $true, HelpMessage = 'Please specify the Azure AD credential')]
    [Alias('cred')]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$Credential,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCred', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$OAuthURI,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCred', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$ResourceURI = 'https://management.azure.com/'
  )

  #Extract fields from connection (hashtable)
  If ($PSCmdlet.ParameterSetName -eq 'BySPConnection') {
    $bvalidConnectionObject = $false
    if ($AzureServicePrincipalConnection.ContainsKey('Applicationid') -and $AzureServicePrincipalConnection.ContainsKey('TenantId') -and $AzureServicePrincipalConnection.ContainsKey('SubscriptionId')) {
      if ($AzureServicePrincipalConnection.ContainsKey('ServicePrincipalKey')) {

        $ClientId = $AzureServicePrincipalConnection.ApplicationId
        $ClientSecret = $AzureServicePrincipalConnection.ServicePrincipalKey
        $TenantId = $AzureServicePrincipalConnection.TenantId
        $bvalidConnectionObject = $true
      }
    }

    if (!$bvalidConnectionObject) {
      Write-Error "The connection object is invalid. please ensure the connection object type must be 'Key Based AzureServicePrincipal'."
      Exit -1
    }
  }

  If ($PSCmdlet.ParameterSetName -eq 'ByCred') {
    $ClientId = $Credential.UserName
    $ClientSecret = $Credential.GetNetworkCredential().Password
  }

  #URI to get oAuth Access Token
  If (!$PSBoundParameters.ContainsKey('oAuthURI')) {
    $oAuthURI = "https://login.microsoftonline.com/$TenantId/oauth2/token"
  }

  #oAuth token request

  $body = 'grant_type=client_credentials'
  $body += '&client_id=' + $ClientId
  $body += '&client_secret=' + [Uri]::EscapeDataString($ClientSecret)
  $body += '&resource=' + [Uri]::EscapeDataString($ResourceURI)

  $response = Invoke-RestMethod -Method POST -Uri $oAuthURI -Headers @{} -Body $body

  $Token = "Bearer $($response.access_token)"
  $Token
}
Function Get-AzureADTokenForUser {
  [CmdletBinding()]
  [OutputType([string])]
  PARAM (
    [Parameter(Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [Alias('tID')]
    [String]$TenantID,

    [Parameter(Mandatory = $true)][Alias('cred')]
    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    $Credential,

    [Parameter(Mandatory = $true)]
    [String][ValidateNotNullOrEmpty()]$OAuthURI,

    [Parameter(Mandatory = $true)]
    [String][ValidateNotNullOrEmpty()]$ResourceURI
  )
  Try {
    $Username = $Credential.Username
    $Password = $Credential.Password

    # Set well-known client ID for Azure PowerShell
    $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'

    # Set Authority to Azure AD Tenant
    $authority = 'https://login.microsoftonline.com/common/' + $TenantID
    Write-Verbose "Authority: $OAuthURI"

    $AADcredential = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential]::new($UserName, $Password)
    $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($OAuthURI)
    $authResult = $authContext.AcquireTokenAsync($ResourceURI, $clientId, $AADcredential)
    $Token = $authResult.Result.CreateAuthorizationHeader()
  }
  Catch {
    Throw $_
    $ErrorMessage = 'Failed to aquire Azure AD token.'
    Write-Error -Message $ErrorMessage
  }
  $Token
}

Function Get-AzureADTokenForUserInteractive {
  [CmdletBinding()]
  [OutputType([string])]
  PARAM (
    [Parameter(Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [Alias('tID')]
    [String]$TenantID,

    [Parameter(Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$UserName,

    [Parameter(Mandatory = $true)]
    [String][ValidateNotNullOrEmpty()]$OAuthURI,

    [Parameter(Mandatory = $true)]
    [String][ValidateNotNullOrEmpty()]$ResourceURI
  )
  Try {

    # Set well-known client ID for Azure PowerShell
    $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
    # Set redirect URI for Azure PowerShell
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    # Set Authority to Azure AD Tenant
    Write-Verbose "Authority: $OAuthURI"

    $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($oAuthURI)
    $promptBehavior = [ Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
    if ($PSBoundParameters.ContainsKey('UserName')) {
      $userIdentifier = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier]::new($UserName, [Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifierType]::RequiredDisplayableId)
      $authResult = $authContext.AcquireTokenAsync($ResourceURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.platformParameters]::new($promptBehavior), $userIdentifier)
    }
    else {
      $authResult = $authContext.AcquireTokenAsync($ResourceURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.platformParameters]::new($promptBehavior))
    }
    $token = $authResult.Result.CreateAuthorizationHeader()
  }
  Catch {
    Throw $_
    $ErrorMessage = 'Failed to aquire Azure AD token.'
    Write-Error -Message $ErrorMessage
  }
  $token
}

Function Get-AzureADTokenForCertServicePrincipal {
  [CmdletBinding()]
  [OutputType([string])]
  PARAM (
    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $true)]
    [Alias('Con', 'Connection')]
    [Object]$AzureServicePrincipalConnection,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [String]$TenantID,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true)]
    [ValidateScript( {
        try {
          [System.Guid]::Parse($_) | Out-Null
          $true
        }
        catch {
          $false
        }
      })]
    [String]$ApplicationId,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true, HelpMessage = 'Please specify the pfx Certificate file path')]
    [ValidateScript( { test-path $_ })]
    [string]$CertFilePath,

    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $true, HelpMessage = 'Please specify the pfx Certificate file path')]
    [ValidateNotNullOrEmpty()]
    [SecureString]$CertFilePassword,

    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true, HelpMessage = "Please specify the Thumbprint of the certificate located in 'Cert:\LocalMachine\My' cert store")]
    [ValidateScript( { test-path "Cert:\LocalMachine\My\$_" })]
    [string]$CertThumbprint,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$OAuthURI,

    [Parameter(ParameterSetName = 'BySPConnection', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertFile', Mandatory = $false)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $false)]
    [String][ValidateNotNullOrEmpty()]$ResourceURI = 'https://management.azure.com/'
  )

  #Extract fields from connection (hashtable)
  If ($PSCmdlet.ParameterSetName -eq 'BySPConnection') {
    $bvalidConnectionObject = $false
    if ($AzureServicePrincipalConnection.ContainsKey('Applicationid') -and $AzureServicePrincipalConnection.ContainsKey('TenantId') -and $AzureServicePrincipalConnection.ContainsKey('SubscriptionId')) {
      if ($AzureServicePrincipalConnection.ContainsKey('CertificateThumbprint')) {

        $ApplicationId = $AzureServicePrincipalConnection.ApplicationId
        $CertThumbprint = $AzureServicePrincipalConnection.CertificateThumbprint
        $TenantId = $AzureServicePrincipalConnection.TenantId
        $bvalidConnectionObject = $true
      }
    }

    if (!$bvalidConnectionObject) {
      Write-Error "The connection object is invalid. please ensure the connection object type must be 'AzureServicePrincipal'."
      Exit -1
    }
  }

  #Get the cert X509Certificate object
  If ($PSCmdlet.ParameterSetName -eq 'ByCertFile') {
    try {
      $marshal = [System.Runtime.InteropServices.Marshal]
      $ptr = $marshal::SecureStringToBSTR($CertFilePassword)
      $CertFilePlainPassword = $marshal::PtrToStringBSTR($ptr)
      $marshal::ZeroFreeBSTR($ptr)
      $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($CertFilePath, $CertFilePlainPassword)
    }
    Catch {
      Throw $_.Exception
      Exit -1
    }
  }
  else {
    $CertStore = "Cert:\LocalMachine\My"
    $CertStorePath = Join-Path $CertStore $CertThumbprint
    $Cert = Get-Item $CertStorePath
    if (!$Cert) {
      Write-Error "Unable to get cert with thumbprint $CertThumbprint in cert store '$CertStore'."
      exit -1
    }
  }

  #URI to get oAuth Access Token
  If (!$PSBoundParameters.ContainsKey('oAuthURI')) {
    $oAuthURI = "https://login.microsoftonline.com/$TenantId/oauth2/token"
  }

  #oAuth token request
  $ClientCert = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate]::new($ApplicationId, $Cert)
  $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($oAuthURI)
  $Token = ($authContext.AcquireTokenAsync($ResourceUri, $ClientCert)).Result.AccessToken
  $Token = "Bearer $Token"
  $Token
}
New-Alias -Name Add-AzureRMServicePrincipalAccount -Value Add-AzServicePrincipalAccount