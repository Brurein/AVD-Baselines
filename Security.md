# Multi-Session Windows

### S1

Shared locations that users have write access to cannot contain binaries or executables or anything that can lead to code or command execution.

**Why?**

The reason for this baseline is that in multi-session windows shared software locations can be used in exe planting attacks, or DLL Hijacking attacks.  This vector exists on single session windows, but I feel this vector is far more lucritive on multi-session as you can interact with other sessions on the box in a live context. There's no reverse tunnels going over the network or files to be collected later, you can keep the attack on the box where the chance of being detected is lower.

**Ref:**

https://attack.mitre.org/techniques/T1574/002/



### S2 
It is imperitive that folders on the **System** Path are secure ie non-admins cannot write to these locations.

You can check the system path entries with the following Powershell from my PathChecker  script.

```Powershell

#Check PATH Folders
$paths = $env:path -split ";"

$paths | %{

 if($_.Trim() -eq ""){
	 continue;
 }

 #Test for non existent SYSTEM PATH folders

 if( -not (Test-Path -Path "$_")){
	 Write-Host "[CRITICAL] Path System Variable $($_) does not exist."
 }
 else
 {
	 #Look for potentially bad permissions
	 Test-WriteACL $_ "NT AUTHORITY\Everyone"
	 Test-WriteACL $_ "NT AUTHORITY\Authenticated Users"
	 Test-WriteACL $_ "BUILTIN\Users"
 }

}

```

**Why?**

If a user gains control over any folder on the System Path, you can use it to perform DLL Hijacking, Exe Planting, by abusing software which naively use the System Path as a search path.  This can lead to full System Privileges being obtained, if there's a poorly coded service which makes use of the insecure search path.

**Ref:**

[Mitre Path Interception](https://attack.mitre.org/techniques/T1574/007/)
[Mitre Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008/)



### S3
The system drive root ACL's should have all non admin users restricted to read & execute only and any notion of write access should be removed.

This can easilly be achieved with the following:

```cmd

icacls.exe c:\ /remove:g "Authenticated Users"

```

Additionally you can check for bad folder permissions using the following from my Path Checker Script:

```Powershell

$Folders = (gci c:\ -Directory ).FullName

$Folders | %{

 Test-WriteACL $_ "NT AUTHORITY\Everyone"
 Test-WriteACL $_ "NT AUTHORITY\Authenticated Users"
 Test-WriteACL $_ "BUILTIN\Users"
 
}

```

**Why?**

If a non-admin user is allowed to abirtrailly write files or folders to the root of the System Drive, this can be used in some cases to exploit Unquoted paths, dll hijacking, exe planting. Imagine what would happen if you created a reverse shell on windows called "Program.exe" in "c:\\". Yes that does work if you have the right permissions.


**Ref:**

[Mitre Unqoted Path](https://attack.mitre.org/techniques/T1574/009/)


