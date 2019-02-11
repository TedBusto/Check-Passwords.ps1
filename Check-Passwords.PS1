<#
.Synopsis
   Calls the haveibeenpwned API to check if a password is contained on a breach list
.DESCRIPTION
   Takes a password and hashes to a SHA-1 hash, then sends the first 5 characters to the haveibeenpwned API. The response contains all the hashes that match and is compared on the local machine.
.EXAMPLE
   Check-Password
.EXAMPLE
   Check-Password -password P@ssw0rd!
.INPUTS
   None
.OUTPUTS
   Text declaring number of times breached
.NOTES
   This program does not send complete password hashes over the internet.
.COMPONENT
   Works on the haveibeenpwned API
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   Checks passwords against the haveibeenpwned API.
#>
function Check-Password
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://haveibeenpwned.com/API/v2',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # For demonstration purposes
        [switch]$demo,

        # Doesn't obscure passwords while typing
        [switch]$Insecure,

        # Password you want to check
        $password,

        #Have I been PWNed URL
        $URL = "https://api.pwnedpasswords.com/range/"
    )

    Begin
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (!($password))
        {
                if ($Insecure)
                {
                    $password = Read-Host "Enter the password to check against the haveibeenpwned database"
                }

                else
                {
                    if ($demo)
                    {
                    Write-Host '$SecurePassword = Read-Host "Enter the password to check against the haveibeenpwned database" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)'
                    pause
                    }
                    $SecurePassword = Read-Host "Enter the password to check against the haveibeenpwned database" -AsSecureString
                    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
                    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                }
        }
        if ($demo)
        {
            Write-Host '#http://jongurgul.com/blog/get-stringhash-get-filehash/ 
Function Get-StringHash([String] $String,$HashName = "SHA1") 
{ 
$StringBuilder = New-Object System.Text.StringBuilder 
[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
[Void]$StringBuilder.Append($_.ToString("x2")) 
} 
$StringBuilder.ToString()'
            Pause
        }
        #http://jongurgul.com/blog/get-stringhash-get-filehash/ 
        Function Get-StringHash([String] $String,$HashName = "SHA1") 
        { 
        $StringBuilder = New-Object System.Text.StringBuilder 
        [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
        [Void]$StringBuilder.Append($_.ToString("x2")) 
        } 
        $StringBuilder.ToString()
        }
    if ($demo)
    {
Write-Host '$passHash = Get-StringHash $password'
Write-Host $passHash
Pause
    }
    $passHash = Get-StringHash $password
       
    }
    Process
    {
        if ($demo) 
        {
Write-Host '$results = Invoke-RestMethod -Uri ($url + $passHash.Substring(0,5)) -Method Get'
Pause
$results
Pause
        }
    $results = (Invoke-RestMethod -Uri ($url + $passHash.Substring(0,5)) -Method Get).split("`n")
    
    if ($demo)
    {
    Write-Host 'ForEach ($result in $results)
{
[PSCustomObject]$hash = @{hash=$result.split(":")[0];breachcount=$result.split(":")[1]}
[array]$hashes += $hash
}'
Pause
    }
    
    ForEach ($result in $results)
    {
        [PSCustomObject]$hash = @{hash=$result.split(":")[0];breachcount=$result.split(":")[1]}
        [array]$hashes += $hash
    }
    if ($demo)
    {
Write-Host '$breachcount = ($hashes | Where {$passhash.substring(5).toUpper() -in $_.hash}).breachCount'
Pause
    }
    $breachcount = ($hashes | Where {$passhash.substring(5).toUpper() -in $_.hash}).breachCount
    }
    End
    {
    if ($demo)
    {
    Write-Host 'If ($breachCount -gt 0)
{
Write-Host "Oh no! You've been Pwned $breachCount Times" -ForeGroundColor Red
}
Else
{
    Write-Host "Looks good, your password isn't on haveibeenpwned.com" -foreGroundColor Green
}'
Pause
    }
    If ($breachCount -gt 0)
    {
        Write-Host "Oh no! You've been Pwned $breachCount Times" -ForegroundColor Red
    }
    Else
    {
        Write-Host "Looks good, your password isn't on haveibeenpwned.com" -ForegroundColor Green
    }
    }
}
