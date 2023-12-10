Import-ActiveDirectory

#Input domain credientials and verifies them.
$authenticate = $true
$attempts = 3
while ($authenticate) {
    $domain_username = Read-Host -Prompt "Enter YOUR ADMIN domain\username"
    $credientials = Get-Credential -UserName $domain_username -Message 'Enter Admin Password'
    try {
        $session = New-PSSession -ComputerName 'ServerName' -Credential $credientials -ErrorAction Stop
        Remove-PSSession $session
        Write-Host "Authentication successful" -ForegroundColor Green
        $authenticate = $false
    } catch {
        $attempts = $attempts - 1
        if ($attempts -eq 0){
            Write-Host "Too many failed attempts. Exiting console." -ForegroundColor Red
            exit
        }
        Write-Host "Failed to authenticate please try again. $attempts attempts remaining." -ForegroundColor Red
    }
}

$name = whoami.exe
$name = $name.split("\")
$login = $name[1]

Invoke-Command -ComputerName "ServerName" -Credential $credientials -ScriptBlock{
    $login = $using:login
    $login_name = Get-ADUser -Identity $login
    $From = $login_name.UserPrincipalName
    $EmailTo = "desktoptechs@domain.com", "SecurityAlert@domain.com"

    Import-Module ActiveDirectory
    
    #Ask for Terminated useraccount, check to make sure the username is active and not already departed.
    $credientials = $using:credientials
    
    $validusername = $true
    while ($validusername){
        $username_test = Read-Host -Prompt "Please enter the username of the terminated account"
        try {
            $username_details = Get-ADUser -Identity $username_test -ErrorAction Stop
            $name_string = $username_details.Name.ToString()
            if ($username_details.distinguishedName -eq "CN=$name_string,OU=Departed Users,DistinguishedName"){
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

    #Specify a time the script will run. 
    $time = Read-Host -Prompt "What time would you like to disable the account?"
    $targetTime = [datetime]$time
    $buffer = [timespan]::FromMinutes(5)
    $currentTime = Get-Date

    #Verify the Account Termination
    $account_name = $username_details.Name
    $username_verify = Read-Host -Prompt "Are you sure you want to Terminate the following user? (Y/N) $account_name"
    if ($username_verify -eq 'Y' -or $username_verify -eq 'y'){
        
    }else{
        exit
    }

    while ($currentTime -lt $targetTime -or $currentTime -gt ($targetTime + $buffer)) {
        Start-Sleep -Seconds 5  
        $currentTime = Get-Date
    }

    #Reset Password
    Set-ADAccountPassword -Identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "Welcome!@#" -Force)

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
        if ($membership.distinguishedName -eq 'CN=Domain Users,OU=General SG,OU=Security Groups,OU=DistinguishedName')
        {
        continue
        }
        Remove-ADPrincipalGroupMembership -Identity $username -MemberOf $membership.distinguishedName -Credential $credientials -Confirm:$false
    }

    #Move AD account to Departed User's OU
    $username_details = Get-ADUser -Identity $username
    Move-ADObject -Identity $username_details.distinguishedName -TargetPath 'OU=Departed Users,DC=DistinguishedName' -Credential $credientials

    #Move the Home and Profile folders to the Archive server. 
    $Folder_Name = $username
    $Path1 = "\\ServerName\home_archive\$Folder_Name"
    New-Item -Path $Path1 -ItemType Directory 
    $Path2 = "\\ServerName\profile_archive\$Folder_Name"
    New-Item -Path $Path2 -ItemType Directory 

    $Source_Home_Folder = "\\ServerName\doi_share\home_folder\$Folder_Name"
    $Destination_Home_Folder = "\\ServerName\HOME_ARCHIVE\$Folder_name"

    $Source_Profile_folder = "\\ServerName\USER_FOLDER_REDIRECTION\$Folder_name"
    $Destination_Profile_folder = "\\ServerName\PROFILE_ARCHIVE\$Folder_name"

    #Robocopy Execute
    robocopy $Source_Home_Folder $Destination_Home_Folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
    robocopy $Source_Profile_folder $Destination_Profile_folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 

    #Sends Email with user's memberships
    $fullname = $username_details.Name
    Send-MailMessage -From $From -To $EmailTo -Subject "Departed User $fullname" -body "The Departed account $fullname is now completed. Their home and profile folders have been moved to the Archived Server. Here is a list of Group Memberships he/she was assigned to: `n$assignedgroups" -SmtpServer 'smtp.doi.nycnet' -Port '25'
}
