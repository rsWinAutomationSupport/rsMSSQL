Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement'
[reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null;
$server = new-object Microsoft.SqlServer.Management.Smo.Server("localhost");
$role = New-object Microsoft.SqlServer.Management.Smo.ServerRole($server, "sysAdmin")

function Get-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [pscredential]$User,
        [Boolean]$Admin = $False,
        [ValidateSet("Windows","SQL")]
        [String]$Auth = "SQL",
        [pscredential]$Credential,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )

    #Credential Check: Validating Credential is a PSCredential
    if($Credential.GetType().Name -eq "PSCredential")
    {
    $CredentialOK = $true
    }else{$CredentialOK = $false}
    if($User.GetType().Name -eq "PSCredential")
    {
    $UserOK = $true
    }else{$UserOK = $false}
    

    Return @{
            Name = $Name;
            User = $UserOK;
            Admin = $Admin;
            Auth = $Auth;
            Credential = $CredentialOK;
            Ensure = $Ensure
            }
}

function Set-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [pscredential]$User,
        [Boolean]$Admin = $False,
        [ValidateSet("Windows","SQL")]
        [String]$Auth = "SQL",
        [pscredential]$Credential,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )

    if($psboundparameters.Auth -eq "Windows")
    {
        try{
        if($Credential)
        {
            Write-Verbose "Windows Auth with Credentials Specified. Testing Credential rights."
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Machine)
            $AdminExist = ([System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $Credential.username))
            $AdminGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($principalContext, "Administrators")
            $AdminMember = [bool]([System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $Credential.username).IsMemberOf($AdminGroup))
            $CredValid = [bool]$principalContext.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password)
            $GroupSQL = [bool]($role.enumMemberNames().contains("BUILTIN\Administrators"))
            if(($AdminExist) -and ($AdminMember) -and ($CredValid) -and ($GroupSQL))
            {
                Write-Verbose "Credential test successful. Connecting to SQL with Admin Credentials."
                $server = Login-SQLServer -Auth $Auth -Cred $Credential
            }else{Write-Verbose "Credential test Failed. Check your Credential object"}
        }else{Write-Verbose "Windows Auth without Credentials specified. Using DSC Run Account."}
        }
        finally
        {
        if ($verifyCredential -ne $null)
        {
            $verifyCredential.Dispose()
            $AdminGroup.Dispose()
        }
        $principalContext.Dispose()
        }
    }
    elseif ($psboundparameters.Auth -eq "SQL")
    {
        if($Credential)
        {
            Write-Verbose "SQL Auth with Credentials Specified. Testing Credential rights."
            $UserSQL = [bool]($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -match $Credential.UserName)
            $GroupSQL = [bool]($role.enumMemberNames()| Where-Object {$_ -match $Credential.UserName})
            if(($userSQL) -and ($GroupSQL))
            {
                Write-Verbose "Credential test successful. Connecting to SQL with SQL Credentials."
                $server = Login-SQLServer -Auth $Auth -Cred $Credential
            }
        }elseif(Test-Path "C:\SQL_SA_Password.txt")
        {
            $pass = (Get-Content C:\SQL_SA_Password.txt -Delimiter ' = ')[1]
            if (($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -match "sa"))
            {
                Write-Verbose "Creating sa user PSCredential"
                $secpass = ConvertTo-SecureString $pass -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential ("sa", $secpass)
                Write-Verbose "Connecting to SQL with SA Credentials."
                $server = Login-SQLServer -Auth $Auth -Cred $Credential
            }
        }
    }
    
    if($psboundparameters.Ensure -eq "Present")
    {
        # Creating new SQL User Account.
        if(!($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -eq $User.UserName))
        {
            $login = new-object Microsoft.SqlServer.Management.Smo.Login($server, $User.UserName)
            $login.LoginType = 'SqlLogin'
            $login.PasswordPolicyEnforced = $false
            $login.PasswordExpirationEnabled = $false
            $login.Create($User.GetNetworkCredential().Password)
            if($Admin)
            {
                $role = $null
                $role = New-object Microsoft.SqlServer.Management.Smo.ServerRole($server, "sysAdmin")
                $role.AddMember($User.UserName)
            }
        }
        # Updating password for an exising SQL User Account to match State.
        elseif(($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -eq $User.UserName))
        {
            $login = $server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -eq $User.UserName
            $login.ChangePassword($User.GetNetworkCredential().Password, $true, $false)
        }
    }
    elseif(($psboundparameters.Ensure -eq "Absent") -and ($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -eq $User.UserName))
    {
        $login = $server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -eq $User.UserName
        $login.drop()
    }
}

function Test-TargetResource
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [pscredential]$User,
        [Boolean]$Admin = $False,
        [ValidateSet("Windows","SQL")]
        [String]$Auth = "SQL",
        [pscredential]$Credential,
        [ValidateSet("Present", "Absent")]
        [string] $Ensure = "Present"
    )

    #User Check: Test if User exists and has perm.
    
    
    if(($server.Logins | Where-Object LoginType -eq "SqlLogin" | Where-Object Name -match $User.UserName))
    {
        Write-Verbose "Verify user account in Role membership"
        $AdminCheck = [bool]($role.enumMemberNames()| Where-Object {$_ -match $User.UserName})
        Write-Verbose "Testing User account login to SQL"
        $server = Login-SQLServer -Auth SQL -Cred $User
        if($server.Logins -ne $null){$UserCheck = $true}
    }else{
        $UserCheck = $false
        $AdminCheck = $false
    }
    if($Ensure = "Present")
    {
        if(($UserCheck) -and ($AdminCheck -match $Admin))
        { return $true } else { return $false }
    }
    if($Ensure = "Absent")
    {
        if(!($UserCheck))
        { return $true } else { return $false }
    }

}

Function Login-SQLServer
{
    param(
    [Parameter(Mandatory)]
    [ValidateSet("Windows","SQL")]
    [string]$Auth,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [pscredential]$Cred
    )
    if($auth -eq "Windows"){$NTmode = $true}else{$NTmode = $false}
    $server = $null
    $server = new-object Microsoft.SqlServer.Management.Smo.Server("localhost")
    $server.ConnectionContext.ConnectAsUser = $NTMode
    $server.ConnectionContext.LoginSecure = $true
    $server.ConnectionContext.ConnectAsUserName = $Cred.UserName
    $server.ConnectionContext.ConnectAsUserPassword =$Cred.GetNetworkCredential().Password
    Write-Verbose "$server.Loginmode"
    Return $server
}


Export-ModuleMember -Function *-TargetResource