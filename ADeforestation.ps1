function Find-localadmins-wmi
{
 [CmdletBinding()] Param(
        
        [Parameter( Mandatory = $False)]
        [String]
        $ComputerName

    )
    Write-Output "Finding local-admins..."

    $groupMembers = get-wmiobject win32_groupUser -ComputerName $ComputerName -ErrorAction Stop
    $groupMembers = $groupMembers | where { $_.GroupComponent -like "*Administrators*"}
    foreach ($member in $groupMembers)
    {
        $name = $member.PartComponent.Split("=")
        $ugName = $name[2].Replace('"',"")
        if (($name[1]) -match $member.PSComputerName )
        {
        $ugName + " is Local Admin to machine"
         
        }
        else
        {
        $ugName
        }
     }

}
function Session-Machine
{
 [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $ComputerName
    )
    if($ComputerName)
    {
    Write-Output "Finding Sessions in a pc"
    Invoke-Command -ComputerName $Computer   -ScriptBlock {quser}
    }

    
    
}
function Misconfigure-ACL-Object
{
 [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="grant_user", Mandatory = $False)]
        [String]
        $grant_user,
        [Parameter(Mandatory=$False)]
        [String]
        $User,
        [Parameter( Mandatory = $False)]
        [String]
        $Group,
        [Parameter( Mandatory = $False)]
        [String]
        $OU,
        [Parameter( Mandatory = $False)]
        [String]
        $Rights
     )  
     if($User)
     {
        $DistinguishedName=(Get-ADUser -Identity $User.Replace('"',"")).DistinguishedName
     }
     elseif($Group)
     {
     $DistinguishedName=(Get-ADGroup -Identity $Group).DistinguishedName
     }
     elseif($OU)
     {
     $DistinguishedName=(Get-ADOrganizationalUnit -Filter 'Name -like $OU' ).DistinguishedName
     }
     $loca="AD:\"+$DistinguishedName
     $acl=(Get-Acl $loca)
     $Useridentity=(Get-ADUser  -Identity $grant_user)
     $sid = [System.Security.Principal.SecurityIdentifier] $Useridentity.SID
     $identity = [System.Security.Principal.IdentityReference] $SID
     if($Rights)
     {
     $adRights = [System.DirectoryServices.ActiveDirectoryRights] $Rights
     }
     else
     {
     $adRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
     }
     $type = [System.Security.AccessControl.AccessControlType] "Allow"
     $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
     $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$inheritanceType
     $acl.AddAccessRule($ace)
     Set-acl -aclobject $acl $loca
}
function Reset-Acl
{
[CmdletBinding()] Param(
        
        [Parameter( Mandatory = $False)]
        [String]
        $User,
        [Parameter( Mandatory = $False)]
        [String]
        $Group,
        [Parameter( Mandatory = $False)]
        [String]
        $Remove_User
     )
     if($User)
     {
        $DistinguishedName=(Get-ADUser -Identity $User.Replace('"',"")).DistinguishedName
      }
      elseif($Group)
      {
      $DistinguishedName=(Get-ADGroup -Identity $Group).DistinguishedName
      }
    $loca="AD:\"+$DistinguishedName
    $acl=(Get-Acl $loca)
       
    foreach($acc in $acl.access ) 
    { 
    $value = $acc.IdentityReference.Value 
    if($value -match $Remove_User) 
    { 
        $ACL.RemoveAccessRule($acc)
        Set-Acl -AclObject $acl $loca -ErrorAction Stop 
        
    } 

    }
}
function Make-LocalAdmin
{
[CmdletBinding()] Param(
        
        [Parameter( Mandatory = $True)]
        [String]
        $Computer,
        [Parameter( Mandatory = $False)]
        [String]
        $Group,
        [Parameter( Mandatory = $False)]
        [String]
        $User,
        [Parameter( Mandatory = $True)]
        [String]
        $Domain
        )
        if($User)
        {
        $domainuser=$Domain+"\"+$User
        $scriptblock = $ExecutionContext.InvokeCommand.NewScriptBlock("net localgroup administrators $domainuser /ADD")
        }
        elseif($Group)
        {
         
        $domaingroup=$Domain+"\"+$Group
        $scriptblock = $ExecutionContext.InvokeCommand.NewScriptBlock("net localgroup administrators $domaingroup /ADD")
        }
        Invoke-Command -ComputerName $Computer   -ScriptBlock $scriptblock

        
}
function Remove-LocalAdmin
{
[CmdletBinding()] Param(
        
        [Parameter( Mandatory = $True)]
        [String]
        $Computer,
        [Parameter( Mandatory = $False)]
        [String]
        $Group,
        [Parameter(Mandatory = $False)]
        [String]
        $User,
        [Parameter( Mandatory = $True)]
        [String]
        $Domain
        )
        
      if($User)
        {
        $domainuser=$Domain+"\"+$User
        $scriptblock = $ExecutionContext.InvokeCommand.NewScriptBlock("net localgroup administrators $domainuser /delete")
        }
        elseif($Group)
        {
         
        $domaingroup=$Domain+"\"+$Group
        $scriptblock = $ExecutionContext.InvokeCommand.NewScriptBlock("net localgroup administrators $domaingroup /delete")
        }
        Invoke-Command -ComputerName $Computer   -ScriptBlock $scriptblock

        
}
function Enable-wmi-firewall
{
[CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="User",Position = 0, Mandatory = $False)]
        [String]
        $Computer
        )
        $scriptblock = $ExecutionContext.InvokeCommand.NewScriptBlock('netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes')
        Invoke-Command -ComputerName $Computer   -ScriptBlock $scriptblock
}
function Get-Perm-Object
{
 [CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="User", Mandatory = $False)]
        [String]
        $User,
        [Parameter(ParameterSetName="Group", Mandatory = $False)]
        [String]
        $Group,
        [Parameter(ParameterSetName="OU", Mandatory = $False)]
        [String]
        $OU,
        [Parameter(ParameterSetName="GPO", Mandatory = $False)]
        [String]
        $GPO
     )  
     if($User)
     {
        $DistinguishedName=(Get-ADUser -Identity $User.Replace('"',"")).DistinguishedName
        $loca="AD:\"+$DistinguishedName
        $acl=(Get-Acl $loca)
        $acl.access
     }
     elseif($Group)
     {
        $DistinguishedName=(Get-ADGroup -Identity $Group).DistinguishedName
        $loca="AD:\"+$DistinguishedName
        $acl=(Get-Acl $loca)
        $acl.access
     }
     elseif($OU)
     {
        $DistinguishedName=(Get-ADOrganizationalUnit -Filter 'Name -like $OU' ).DistinguishedName
        $loca="AD:\"+$DistinguishedName
        $acl=(Get-Acl $loca)
        $acl.access
     }
     elseif($GPO)
     {
     $GPPerm=(Get-GPPermission -Name $GPO -All)
     $GPPerm

     }
     
}
function Change-gpp-perm
{


[CmdletBinding()] Param(
        
        [Parameter(ParameterSetName="Name", Mandatory = $False)]
        [String]
        $Name,
        [Parameter( Mandatory = $True)]
        [String]
        $TargetName,
        [Parameter( Mandatory = $True)]
        [String]
        $TargetType,
        [Parameter( Mandatory = $True)]
        [String]
        $PermissionLevel,
        [Parameter(Mandatory=$True)]
        [Switch]
        $Remove
     )
    
     if($Remove)
     {
     Set-GPPermission -Name $Name -Replace -PermissionLevel None -TargetName $TargetName  -TargetType $TargetType
     }
     else
     {
      Set-GPPermission -Name $Name -TargetName $TargetName -TargetType $TargetType -PermissionLevel $PermissionLevel
     }
}

     






