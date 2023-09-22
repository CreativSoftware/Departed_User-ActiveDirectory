Import-Module ActiveDirectory

#Input your domain admin credentials
$From = Read-Host -Prompt "Please enter YOUR Email Address"
$domain_username = Read-Host -Prompt "Enter YOUR ADMIN domain\username"
$credientials = Get-Credential -UserName $domain_username -Message 'Enter Admin Password'

#Prompt for the username of terminated user
$username = Read-Host -Prompt "Please enter the username of the terminated account"

#Email Setup
$EmailTo = "desktoptechs@doi.nyc.gov", "SecurityAlert@doi.nyc.gov"

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

# Create the folder on Home and Profile Archive
Invoke-Command -ComputerName "doidc02" -Credential $credientials -ScriptBlock {
    $Folder_Name = $using:username
    $Path1 = "\\Server\Path\$Folder_Name"
    New-Item -Path $Path1 -ItemType Directory 
    $Path2 = "\\Server\Path\$Folder_Name"
    New-Item -Path $Path2 -ItemType Directory 
    
    $Source_Home_Folder = "\\Server\Path\home_folder\$Folder_Name"
    $Destination_Home_Folder = "\\Server\HOME_ARCHIVE\$Folder_name"
    
    $Source_Profile_folder = "\\Server\Path\$Folder_name"
    $Destination_Profile_folder = "\\Server\Path\$Folder_name"
    
    #--------------Execute Command--------------------------------------------
    robocopy $Source_Home_Folder $Destination_Home_Folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
    robocopy $Source_Profile_folder $Destination_Profile_folder /COPYALL /Z /E /W:1 /R:2 /tee /Move 
}

#--------------Send Email when completed----------------------------------
$fullname = $username_details.Name
Send-MailMessage -From $From -To $EmailTo -Subject "Departed User $fullname" -body "The Departed account $fullname is now completed. Their home and profile folders have been moved to the Archived Server. Here is a list of Group Memberships he/she was assigned to: `n$assignedgroups" -SmtpServer 'smtp.doi.nycnet' -Port '25'
