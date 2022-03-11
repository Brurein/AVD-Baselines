function Get-Icacls(){
    param([String]$path)

    if($path -ne "C:\"){
        $path = $path.TrimEnd('\')
    }

    $out =  & "C:\Windows\System32\icacls.exe" "$($path)" | Out-String
    
    $out = $out -split "`r`n"
    
    $parsed = @()

    foreach($linex in $out){

        $line = $linex.Trim();

        if($line -eq ""){
            continue
        }

        if($line.ToLower().startsWith("successfully")){
            continue
        }

        if($line.ToLower().startsWith("c:\")){
            $line = $line.SubString($line.indexOf(" ")+1)
        }

        $line_parts = $line -split ":"
        #write-host $line_parts
        $UserPrincipal = $line_parts[0]
        $permissions = $line_parts[1]

        $permission_set = $permissions -replace '\(','' -split '\)' | ?{ $_ -ne ""}

        #write-host "User: $($UserPrincipal)"
        #Write-Host $permission_set

        #yield return
        $parsed += [pscustomobject]@{
            User = $UserPrincipal
            Permissions = $permission_set
        }
    }

    return $parsed
}

function Test-ACL(){
    param([String]$Path, [String]$TestACL)

    $Permissions = Get-Acl "$Path" | Select -ExpandProperty Access

    if(($Permissions | ?{ $_.IdentityReference -eq $TestACL }).Count -gt 0){
        Write-Host "[Critical] $Path permissions are too permissive. Remove '$($TestACL)' from ACL's" 
    }

}

function Test-WritePerm($Perm){
    #All write permissions from: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
    $bad_perms = $("F", "M", "W", "D", "WDAC", "WO", "AS", "GW", "GA", "WD", "AD", "WEA", "DC", "WA" )

    if($bad_perms -contains $Perm){
        return $true
    }

    return $false
}

function Test-WriteACL (){
    param([String]$Path, [String]$TestACL)

    $Icacls = Get-Icacls "$Path"

    foreach($cacl in $Icacls){
        
        if($cacl.User -eq $TestACL){

            foreach ($perm in $cacl.Permissions){
                
                if(Test-WritePerm $perm){

                    Write-Host "Misconfigured Permission: '$($cacl.User)' has '$perm' permission on $Path"

                }

            }

        }

    }

}


Test-WriteACL "C:\" "NT AUTHORITY\Everyone"
Test-WriteACL "C:\" "NT AUTHORITY\Authenticated Users"
Test-WriteACL "C:\" "BUILTIN\Users"

#Check PATH Folders

$paths = $env:path -split ";" 

$paths | %{

    if($_.Trim() -eq ""){
        continue;
    }
    else{
        write-host "Testing: $_"
    }

   # write-host "Path: $_"
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



#Check for writeable folders in the root filesystem

$Folders = (gci c:\ -Directory ).FullName

$Folders | %{
    Test-WriteACL $_ "NT AUTHORITY\Everyone"
    Test-WriteACL $_ "NT AUTHORITY\Authenticated Users"
}




