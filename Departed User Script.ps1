Import-Module ActiveDirectory

#Prompt for the username of terminated user
$username = Read-Host -Prompt "Please enter the username of the terminated account"

#Input your domain admin credentials
$domain_username = Read-Host -Prompt "Enter your domain\username"
$credientials = Get-Credential -UserName $domain_username -Message 'Enter Password'

#Disable user account
Disable-ADAccount -Identity $username -Credential $credientials

#Remove all memberships from AD account
$membershipgroups = Get-ADPrincipalGroupMembership -Identity $username
foreach ($membership in $membershipgroups){
    if ($membership.distinguishedName -eq 'CN=Domain Users,OU=General SG,OU=Security Groups,OU=Groups,DC=DOI,DC=NYCNET')
    {
    continue
    }
    Remove-ADPrincipalGroupMembership -Identity $username -MemberOf $membership.distinguishedName -Credential $credientials -Confirm:$false
}

#Move AD account to Departed User's OU
$username_details = Get-ADUser -Identity $username
Move-ADObject -Identity $username_details.distinguishedName -TargetPath 'OU=Departed Users,DC=DOI,DC=NYCNET' -Credential $credientials