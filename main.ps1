Import-Module ActiveDirectory

#Email Setup
$From = Read-Host -Prompt "Please enter YOUR Email Address"
$EmailTo = "email2@test.com", "email@test.com"

#Input your domain admin credentials
$domain_username = Read-Host -Prompt "Enter YOUR ADMIN domain\username"
$credientials = Get-Credential -UserName $domain_username -Message 'Enter Admin Password'

#Ask for Terminated useraccount, check to make sure the username is active.
$validusername = $true
while ($validusername){
    $username_test = Read-Host -Prompt "Please enter the username of the terminated account"
    try {
        $username_details = Get-ADUser -Identity $username_test -ErrorAction Stop
        $name_string = $username_details.Name.ToString()
        if ($username_details.distinguishedName -eq "CN=$name_string,distinguishedName"){
            Write-Host "The user $name_string is already departed." -ForegroundColor Red
            $choice = Read-Host "Would you like to try another username? (Y/N)"
            if ($choice -eq 'N' -or $choice -eq 'n'){
                exit
            }else{
                continue
            }
        }
        $username = $username_details.SamAccountName
        $validusername = $false
        
    } catch {
        Write-Host "The username '$username_test' does not exist." -ForegroundColor Red
        $choice = Read-Host "Would you like to try another username? (Y/N)"
        
        if ($choice -eq 'N' -or $choice -eq 'n'){
            exit
        }
    }
}

#Verify the Account termination
$username_name = $username_details.Name
$username_verify = Read-Host -Prompt "Are you sure you want to Terminate the following user? (Y/N) $username_name"
if ($username_verify -eq 'Y' -or $username_verify -eq 'y'){
    
}else{
    exit
}

#Specify a time the script will run.
$time = Read-Host -Prompt "What time would you like disabled the account?"
$targetTime = [datetime]$time
$buffer = [timespan]::FromMinutes(5)
$currentTime = Get-Date

while ($currentTime -lt $targetTime -or $currentTime -gt ($targetTime + $buffer)) {
    Start-Sleep -Seconds 5  
    $currentTime = Get-Date
}

#Assigned memberships
$assignedgroups = Get-ADPrincipalGroupMembership -Identity $username | Select-Object Name | Out-String

#Disable user account
Disable-ADAccount -Identity $username -Credential $credientials

#clear the Manager and Direct report fields
Set-ADUser -Identity $username -Clear Manager -Credential $credientials
$directreports = Get-ADUser -Identity $username -properties DirectReports | select-object -ExpandProperty DirectReports
foreach($user in $directreports){
    Set-ADUser -Identity $user -Clear Manager -Credential $credientials
}

#Remove all memberships from AD account
$membershipgroups = Get-ADPrincipalGroupMembership -Identity $username

foreach ($membership in $membershipgroups){
    if ($membership.distinguishedName -eq 'DistiguishedName')
    {
    continue
    }
    Remove-ADPrincipalGroupMembership -Identity $username -MemberOf $membership.distinguishedName -Credential $credientials -Confirm:$false
}

#Move AD account to Departed User's OU
$username_details = Get-ADUser -Identity $username
Move-ADObject -Identity $username_details.distinguishedName -TargetPath 'DistiguishedName' -Credential $credientials

#Move the Home and Profile folders to the Archive server. 
Invoke-Command -ComputerName "servername" -Credential $credientials -ScriptBlock {
    $Folder_Name = $using:username
    $Path1 = "\\Server\Path\$Folder_Name"
    New-Item -Path $Path1 -ItemType Directory 
    $Path2 = "\\Server\Path\$Folder_Name"
    New-Item -Path $Path2 -ItemType Directory 
    
    $Source_Home_Folder = "\\Server\Path\home_folder\$Folder_Name"
    $Destination_Home_Folder = "\\Server\HOME_ARCHIVE\$Folder_name"
    
    $Source_Profile_folder = "\\Server\Path\$Folder_name"
    $Destination_Profile_folder = "\\Server\Path\$Folder_name"
    
    #Robocopy Execute 
    robocopy $Source_Home_Folder $Destination_Home_Folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
    robocopy $Source_Profile_folder $Destination_Profile_folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
}

#Sent Email with user's memberships
$fullname = $username_details.Name
Send-MailMessage -From $From -To $EmailTo -Subject "Departed User $fullname" -body "The Departed account $fullname is now completed. Their home and profile folders have been moved to the Archived Server. Here is a list of Group Memberships he/she was assigned to: `n$assignedgroups" -SmtpServer 'smtp.doi.nycnet' -Port '25'
