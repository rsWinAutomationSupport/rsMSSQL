rsMSSQL
=====

This module contains tools for managing and configuring SQL resources. The module contains each of the following:

rsSQLUser
=====

Allows for the creation and password management of a SQL account using a SQL or Windows Authenticated connection to the instance. Options will allow for the following:

Auth: (Windows, SQL)
- Windows: create user from a specified Windows Account
- SQL: create user from a specified SQL Account
Admin: Will add the user to the SysAdmin role in SQL
Ensure:
- Present: Create or maintain password for user
- Absent: Remove user if found

Minimum requirements of the module are:
Name(module key), User(PSCredential),Ensure(Present,Absent)

If Auth is not specified, SQL AUTH is presumed.
If Credential is not specified:
- Windows AUTH will presume the user account running DSC (generally SYSTEM).
- SQL AUTH will presume 'sa' user and pull the password from a file at the base of the C drive 'SQL_SA_Password.txt'.
Note that SYSTEM does not have required rights in recent versions of SQL by default.
Both User and Credential must be provided as a PScredential object within DSC.



```PoSh
rsSQLUser AppUser
{
    Name = AppUser
    User = $Credentials.AppUser
    Admin = $false
    Auth = "Windows"
    Credential = "$Credentials.AdminUser"
    Ensure = "Present"
}
```

