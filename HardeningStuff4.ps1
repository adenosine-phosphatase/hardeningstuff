# Windows 2016/2012 R2 hardening script 
# Coded by Ivica Stipovic, Aug 2019
# INSTRUCTIONS:
# ===========================================================
# 1. Open powershell console in admin mode
#
# 2. Server needs access to powershell gallery (PSGallery)- if not online, make sure you copy PSGallery locally
# https://microsoft.github.io/DSCEA/mydoc_psgallery_download.html
#============================================================
# 3. Need to manually install those modules before the script executes. Embedding these commands into the script does not do the job.
#
# find-module -name NetworkingDsc -Repository PSGallery | Install-module -Force
# find-module -name AuditPolicyDsc -Repository PSGallery | Install-module -Force
# find-module -name SecurityPolicyDsc -Repository PSGallery | Install-module -Force
#
# 4. The end of the script returns PowerShell into the 'Restricted' mode.
# Therefore, any subsequent execution of the powershell script will be prohibited. 
# You will need to manually re-enable the powershell execution by :
# Set-ExecutionPolicy unrestricted
# WARNING!!! There seems to be one undesirable effect when you Disable "Windows Remote Access Shell"
# WARNING!!! If you set "AllowRemoteShellAccess" to "0" and try to add new role via Server MAnager, it will report error
# WARNING!!! "WinRM plug-in might be corrupted or missing"
# WARNING!!! To mitigate, set "AllowRemoteShellAccess" to "1" (enabled). That should do the work.

# sometimes OS complains on the envelopesize, so setting it to 2048
set-item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048

# setting temporary execution permission for script - will be setup back to restricted at the end of the script
write-host "setting execution policy to allow execution of the script..."
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

Configuration HardeningStuff3 {

	Import-DscResource -ModuleName 'NetworkingDsc'
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
	Import-DscResource -ModuleName 'AuditPolicyDsc'
	Import-DscResource -ModuleName 'SecurityPolicyDsc'
	
	Node 'localhost'
	{
	write-host "[+]Applying Audit Policy Change Success and Failure"
	AuditPolicySubcategory 'Audit Policy Change (Failure)' {
	Name='Audit Policy Change'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Policy Change (Success)' {
	Name='Audit Policy Change'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Credential Validation Success and Failure"
	AuditPolicySubcategory 'Audit Credential Validation (Failure)' {
	Name='Credential Validation'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Credential Validation (Success)' {
	Name='Credential Validation'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit User Account Management"
	AuditPolicySubcategory 'Audit User Account Management (Failure)' {
	Name='User Account Management'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit User Account Management (Success)' {
	Name='User Account Management'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Application Group Management Success and Failure"
	AuditPolicySubcategory 'Audit Application Group Management (Failure)' {
	Name='Application Group Management'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Application Group Management (Success)' {
	Name='Application Group Management'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Security Group Management Success and Failure"
	AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
	Name='Security Group Management'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Security Group Management (Success)' {
	Name='Security Group Management'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Other Account Management Events Success and Failure"
	AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
	Name='Other Account Management Events'
	Ensure='Present'
	AuditFlag='Failure'
	}
	
	AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
	Name='Other Account Management Events'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Computer Account Management Success and Failure"
	AuditPolicySubcategory 'Audit Computer Account Management (Failure)' {
	Name='Computer Account Management'
	Ensure='Present'
	AuditFlag='Failure'
	}
	
	AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
	Name='Computer Account Management'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Process Creation Success and Failure"
	AuditPolicySubcategory 'Audit Process Creation (Failure)' {
	Name='Process Creation'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Process Creation (Success)' {
	Name='Process Creation'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Other Logon/Logoff Events Success and Failure"
	AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
	Name='Other Logon/Logoff Events'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
	Name='Other Logon/Logoff Events'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Special Logon Success and Failure"
	AuditPolicySubcategory 'Audit Special Logon (Failure)' {
	Name='Special Logon'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Special Logon (Success)' {
	Name='Special Logon'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Account Lockout Success and Failure"
	AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
	Name='Account Lockout'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Account Lockout (Success)' {
	Name='Account Lockout'
	Ensure='Present'
	AuditFlag='Success'
	}
	
	write-host "[+]Applying Audit Logoff Success "
	AuditPolicySubcategory 'Audit Logoff (Success)' {
	Name='Logoff'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Logon Success and Failure"
	AuditPolicySubcategory 'Audit Logon (Failure)' {
	Name='Logon'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Logon (Success)' {
	Name='Logon'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Removable Storage Success and Failure"
	AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
	Name='Removable Storage'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Removable Storage (Success)' {
	Name='Removable Storage'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Authorization Policy Change Success"
	AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
	Name='Authorization Policy Change'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Authentication Policy Change Success"
	AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
	Name='Authentication Policy Change'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Sensitive Privilege Use Success and Failure"
	AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
	Name='Sensitive Privilege Use'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
	Name='Sensitive Privilege Use'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Security State Change Success "
	AuditPolicySubcategory 'Audit Security State Change (Success)' {
	Name='Security State Change'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit System Integrity Success and Failure"
	AuditPolicySubcategory 'Audit System Integrity (Failure)' {
	Name='System Integrity'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit System Integrity (Success)' {
	Name='System Integrity'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Security System Extension Success and Failure"
	AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
	Name='Security System Extension'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Security System Extension (Success)' {
	Name='Security System Extension'
	Ensure='Present'
	AuditFlag='Success'
	}
	
	write-host "[+]Applying Audit IPsec driver Success and Failure"
	AuditPolicySubcategory 'Audit IPsec driver (Failure)' {
	Name='IPsec driver'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit IPsec driver (Success)' {
	Name='IPsec driver'
	Ensure='Present'
	AuditFlag='Success'
	}
	write-host "[+]Applying Audit Other System Events Success and Failure"
	AuditPolicySubcategory 'Audit Other System Events (Failure)' {
	Name='Other System Events'
	Ensure='Present'
	AuditFlag='Failure'
	}
	AuditPolicySubcategory 'Audit Other System Events (Success)' {
	Name='Other System Events'
	Ensure='Present'
	AuditFlag='Success'
	}
	
	write-host "[+]Setting Deny log on as a batch job to 'Guests'"
	UserRightsAssignment Denylogonasabatchjob {
	Policy='Deny_log_on_as_a_batch_job'
	Identity='Guests'
	}
	
	UserRightsAssignment Denylogonasaservice {
	Policy='Deny_log_on_as_a_service'
	Identity='Guests'
	}
	write-host "[+]Bypass traverse checking for selected identities"
	UserRightsAssignment Bypasstraversechecking {
	Policy='Bypass_traverse_checking'
	Identity='Everyone,Administrators,Authenticated Users,LOCAL SERVICE,NETWORK SERVICE,Pre-Windows 2000 Compatible Access'
	}
	
	write-host "[+]Enabling Network Security Force Logoff when logon hours expire"
	write-host "[+]Enabling Limit local account use of blank passwords to console logon only"
	write-host "[+]Enabling interactive logon prompt user to change password before expiration to 5"
	write-host "[+]Setting Behavior of the elevation prompt for standard users to 'Prompt for credentials'"
	write-host "[+]Setting Behavior of the elevation prompt for administration in admin approval mode to 'Prompt for consent on the secure desktop'"
	write-host "[+]Enabling Strengthen default permissions of internal system objects"
	write-host "[+]Enabling Switch to the secure desktop when prompting for elevation"
	write-host "[+]Setting Display user information when session is locked to 'User display name only'"
	
	SecurityOption AccountSecurityOptions {
	Name='AccountSecurityOptions'
	Network_security_Force_logoff_when_logon_hours_expire='Enabled'
	Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only='Enabled'
	Interactive_logon_Prompt_user_to_change_password_before_expiration='5'
	User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users='Prompt for credentials' #Ensure 'User Account Control:Behavior of the elevation prompt for standard users' is set to 'Prompt for Credentials'
	User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_approval_Mode='Prompt for consent on the secure desktop' #Ensure 'User Account Control:Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
	System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links='Enabled' #Ensure 'System objects: Strenghten default permissions of internal system objects (e.g. Symbolic Links) is Enabled'
	User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation='Enabled' #Ensure 'User Account Contro;:Switch to the secure desktop when prompting for elevation' is Enabled
	Interactive_logon_Display_user_information_when_the_session_is_locked='User display name only' #THIS REQUIRES CHECKING - Enabled and Disabled are not valid options
	}
	}
	}
	HardeningStuff3
	Start-DscConfiguration -Path .\HardeningStuff3 -Force -Wait

#ensure maximum password age
Write-Host "[+] Setting max password age to 90"
net accounts /maxpwage:90

#ensure minimum password age
Write-Host "[+] Setting min password age to 2"
net accounts /minpwage:2

#ensure minimum password length is 8 characters
Write-Host "[+] Setting min password length to 8"
net accounts /minpwlen:8

Write-host "[+] Setting lockout duration to 30"
net accounts /lockoutduration:30

Write-host "[+] Setting lockout threshold to 55"
net accounts /lockoutthreshold:55

Write-host "[+] Setting lockout windows to 10"
net accounts /lockoutwindow:10

#ensure password history is 12
Write-host "[+] Setting password history to 12"
net accounts /uniquepw:12

#ensure 'Accounts:Administrator account status' is Enabled
Write-host "[+] Setting administrator account status to ON"
net user administrator /active:yes

function SetRegistryHardening()
{
	If (!(Test-Path $registrypath))
		{
			Write-Host "creting new item..."
			New-Item -Path $registrypath -Force | out-null
			New-ItemProperty -Path $registrypath -Name $name -Value $value | out-null
		}
Else
		{
			New-ItemProperty -Path $registrypath -Name $name -Value $value -Force | out-null
		}
}

# Ensure 'Do not allow passwords to be saved' - this is related to Windows RDP services	
write-host "[+] Do not allow passwords to be saved"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="DisablePasswordSaving"
$value=1	
Write-host $registrypath
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'password complexity' is enabled. Seems it is enabled bu default? THIS ONE REQUIRES TESTING
write-host "[+] Enabling password complexity"
$registrypath="HKLM:\Software\Policies\Microsoft Services\AdmPwd"
$name="PasswordComplexity"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Limit local account use of blank passwords to console logon only ' is enabled. 
write-host "[+] Enabling Limit local account use of blank passwords to console logon only"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="LimitBlankPasswordUse"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prompt user to change password before expiration is set to 5 ' is enabled. Seems 5 is by default.
write-host "[+] Setting Prompt user to change password before expiration to 5"
$registrypath="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$name="PasswordExpiryWarning"
$value=5
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'MAxiumum machine account password age' is set to 30. Default is 0.
write-host "[+] Setting Maximum machine account password age to 30"
$registrypath="HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
$name="MaximumPasswordAge"
$value=30
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Disble machine account password changes' is disabled. Seems 0 /disabled is by default
write-host "[+] Disabling 'Disable machine account password changes'"
$registrypath="HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
$name="DisablePasswordChange"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Include command line in process creation events' is disabled. THIS ONE REQUIRES TESTING
write-host "[+] Disabling Include command line in process creation events"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$name="ProcessCreationIncludeCmdLine_Enabled"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow Microsoft accounts to be optional' is disabled. THIS ONE REQUIRES TESTING
write-host "[+] Disabling Allow Microsoft accounts to be optional"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="MSAOptional"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content' is enabled. THIS ONE REQUIRES TESTING
write-host "[+] Enabling Block launching Windows Store apps with Windows Runtime API access from hosted content"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="BlockHostedAppAccessWinRT"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Application:Control Event Log behavior when the log file reaches its maximum size' is disabled.THIS ONE REQUIRES TESTING
write-host "[+] Disabling Application Control:Event log behavior when the log file reaches its maximum size"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application"
$name="Retention"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Application:Specify the maximum log file size (KB)' is set to 32,768 
write-host "[+] Setting Application:Specify the maximum log file size to 32,768 KB"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application"
$name="MaxSize"
$value=32768
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Set the default behavior for AutoRun' is enabled.
write-host "[+] Enabling Set the default behavior for AutoRun"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name="NoAutorun"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Disallow AutoPlay for non-volume devices' is enabled.
write-host "[+] Enabling Disallow AutoPlay for non-volume devices"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$name="NoAutoplayfornonVolume"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not display the password reveal button' is enabled. THIS ONE REQUIRES TESTING.
write-host "[+] Enabling Do not display the password reveal button"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\CredUI"
$name="DisablePasswordReveal"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not show feedback notifications' is enabled. 
write-host "[+] Enabling Do not show feedback notifications"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
$name="DoNotShowFeedbackNotifications"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Disable pre-release features or settings ' is disabled. 
write-host "[+] Disabling 'Disable pre-release features or settings'"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds"
$name="EnableConfigFlighting"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Toggle user control over Insider builds ' is disabled. 
write-host "[+] Disabling Toggle user control over Insider builds"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds"
$name="AllowBuildPreview"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off multicast name resolution ' is enabled. 
write-host "[+] Enabling Turn off multicast name resolution"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
$name="EnableMulticast"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Boot-Start Driver Initialization Policy' is enabled. Seems '3' is by default
write-host "[+] Setting Boot-Start Driver Initialization Policy to 3 meaning 'Good,unknown and bad but critical'"
$registrypath="HKLM:\System\CurrentControlSet\Policies\EarlyLaunch"
$name="DriverLoadPolicy"
$value=3
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off shell protocol protected mode' is disabled. 
write-host "[+] Disabling Turn off shell protocol protected mode"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name="PreXPSP2ShellProtocolBehavior"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure Windows Defender SmartScreen' is enabled. 
write-host "[+] Enabling Configure Windows Defender SmartScreen"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="EnableSmartScreen"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off heap termination on corruption' is disabled.
write-host "[+] Disabling Turn off heap termination on corruption" 
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$name="NoHeapTerminationOnCorruption"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure registry policy processing :Do not apply during periodic background processing' is enabled.
write-host "[+] Enabling Configure registry policy processing : Do not apply during periodic background processing" 
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$name="NoBackgroundPolicy"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off background refresh of Group Policy' is disabled. 
write-host "[+] Disabling Turn off background refresh of Group Policy"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name="DisableBkGndGroupPolicy"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is enabled. 
write-host "[+] Enabling Configure registry policy processing: Process even if the Group Policy objects have not changed"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$name="NoGPOListChanges"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Continue experience on this device' is disabled. 
write-host "[+] Disabling Continue experience on this device"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="EnableCdp"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Enable insecure guest logons' is disabled. 
write-host "[+] Disabling Enable insecure guest logons"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$name="AllowInsecureGuestAuth"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not allow password expiration time longer than required by policy' is enabled. 
write-host "[+] Enabling Do not allow password expiration time longer than required by policy"
$registrypath="HKLM:\Software\Policies\Microsoft Services\AdmPwd"
$name="PwdExpirationProtectionEnabled"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Enable local admin password management' is enabled. 
write-host "[+] Enable local admin password management"
$registrypath="HKLM:\Software\Policies\Microsoft Services\AdmPwd"
$name="AdmPwdEnabled"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off app notifications on the lock screen' is enabled. 
write-host "[+] Enable Turn off app notification on the lock screen"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="DisableLockScreenAppNotifications"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn on convenience PIN sign-in' is disabled. 
write-host "[+] Disable Turn on convenience PIN sign-in"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="AllowDomainPINLogon"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not enumerate connected users on domain-joined computers' is enabled. 
write-host "[+] Enable Do not enumerate connected users on domain-joined computers"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="DontEnumerateConnectedUsers"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not display network selection UI' is enabled. 
write-host "[+] Enable Do not display network selection UI"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="DontDisplayNetworkSelectionUI"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Block user from showing account details on sign-in' is enabled. 
write-host "[+] Enable Block user from showing account details on sign-in"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="BlockUserFromShowingAccountDetailsOnSingin"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Untrusted Font blocking' is enabled.  THIS ONE REQUIRES TESTING -"FontBocking' is not a syntax error!
write-host "[+] Enable Untrusted Font blocking"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\MitigationOption"
$name="MitigationOptions_FontBocking"
$value=1000000000000
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is disabled. 
write-host "[+] Disable MSS:Allow ICMP redirects to override OSPF generated routes"
$registrypath="HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters"
$name="EnableICMPRedirect"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'MSS: (NoNameReleaeOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is enabled. 
write-host "[+] Enable MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers"
$registrypath="HKLM:\System\CurrentControlSet\Services\Netbt\Parameters"
$name="NoNameReleaseOnDemand"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 5. 
write-host "[+] Set MSS: (ScreenSaverGracePerios) The time in seconds before the screen saver grace period expires"
$registrypath="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$name="ScreenSaverGracePeriod"
$value=5
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Require domain users to elevate when setting a network location' is enabled. 
write-host "[+] Enable Require domain users to elevate when setting a network location"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Network Connections"
$name="NC_StdDomainUserSetLocation"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is enabled. 
write-host "[+] Enable Prohibit installation and configuration of Network Bridge on your DNS domain network"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Network Connections"
$name="NC_AllowNetBridge_NL"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is enabled. 
write-host "[+] Enable Prohibit use of Internet Connection Sharing on your DNS domain network"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Network Connections"
$name="NC_ShowSharedAccessUI"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prevent the usage of OneDrive for file storage' is enabled. 
write-host "[+] Enable Prevent the usage of OneDrive for file storage"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\OneDrive"
$name="DisableFileSyncNGSC"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow input personalization' is disabled. 
write-host "[+] Disable Allow input personalization"
$registrypath="HKLM:\Software\Policies\Microsoft\InputPersonalization"
$name="AllowInputPersonalization"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure Solicited Remote Assistence' is disabled.
write-host "[+] Disable Configure Solicited Remote Assistence" 
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="fAllowUnsolicited"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure Offer Remote Assistence' is disabled. 
write-host "[+] Disable Configure Offer Remote Assistence"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="fAllowToGetHelp"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Enable RPC Endpoint Mapper Client Authentication' is enabled. 
write-host "[+] Enable RPC Endpoint Mapper Client Authentication"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"
$name="EnableAuthEpResolution"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Restrict Unauthenticated RPC clients' is enabled/authenticated.
write-host "[+] Enable Restrict Unauthenticated RPC clients" 
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Rpc"
$name="RestrictRemoteClients"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prevent downloading of enclosures' is enabled. 
write-host "[+] Enable Prevent downloading of enclosures"
$registrypath="HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds"
$name="DisableEnclosureDownload"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Apply UAC restrictions to local accounts on network logons' is enabled. THIS IS SUSPICIOUS - 0 means active/enabled?
write-host "[+] Enable Apply UAC restrictions to local accounts on network logons"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="LocalAccountTokenFilterPolicy"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'WDigest Authentication (disabling may require KB2871997)' is disabled. 
write-host "[+] Disable WDigest Authentication"
$registrypath="HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
$name="UseLogonCredential"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow indexing of encrypted files' is disabled. 
write-host "[+] Disable Allow indexing of encrypted files"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
$name="AllowIndexingEncryptedStoresOrItems"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Security: Specify the maximum log file size (KB)' is enabled /set to 196,608. 
write-host "[+] Setting Security:Specify the maximum log file size (KB) to 196,608"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"
$name="MaxSize"
$value=196608
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is disabled. 
write-host "[+] Disabling Security: Control Event log behavior when the log file reaches its maximum size"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security"
$name="Retention"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Always prompt for password upon connection' is enabled. 
write-host "[+] Enabling Always prompt for password upon connection"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="fPromptForPassword"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Require secure RPC communication' is enabled. 
write-host "[+] Enabling Require secure RPC communication"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="fEncryptRPCTraffic"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Setup: Specify the maximum log file size (KB)' is enabled to 32,768. 
write-host "[+] Setting Setup:Specify the maximum log file size (KB) to 32,768"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"
$name="MaxSize"
$value=32768
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Setup:Control Event Log behavior when the log file reaches its maximum size' is disabled.
write-host "[+] Disabling Setup:Control Event Log behavior when the log file reaches its maximum size"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup"
$name="Retention"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off the Store application' is enabled.
write-host "[+] Enabling Turn off the Store application"
$registrypath="HKLM:\Software\Policies\Microsoft\WindowsStore"
$name="RemoveWindowsStore"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off the offer to update to the latest version of Windows' is enabled.
write-host "[+] Enabling Turn off the offer to update to the latest version of Windows"
$registrypath="HKLM:\Software\Policies\Microsoft\WindowsStore"
$name="DisableOSUpgrade"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow user control over installs' is disabled.
write-host "[+] Disabling Allow user control over installs"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Installer"
$name="EnableUserControl"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure Automatic Updates:Scheduled install day' is set to 0-Every day.
write-host "[+] Setting Configure Automatic UPdates:Scheduled install day to 0-Every day"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
$name="ScheduledInstallDay"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Minimize the number of simultaneous connections to the internet or a Windows Domain' is enabled.
write-host "[+] Enabling Minimize the number of simultaneous connections to the internet or a Windows Domain"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$name="fMinimizeConnections"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Sign-in last interactive automatically after a system-initiated restart' is disabled.
write-host "[+] Disabling Sign-in last interactive automatically after a system-initiated restart"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="DisableAutomaticRestartSignOn"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off the advertising ID' is enabled.
write-host "[+] Enabling Turn off the advertising ID"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo"
$name="DisabledByGroupPolicy"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow Remote Shell Access' is disabled.
# WARNING!!! Read the header of the script for this setting- this change will cause problems if you want to add new roles to the server
# WARNING!!! via Server Manager - set the below "$value=1" if you need to add role(s) in the future
write-host "[+] Disabling Allow Remote Shell Access"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"
$name="AllowRemoteShellAccess"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn on PowerShell Script Block Logging' is enabled.
write-host "[+] Enabling Turn on PowerShell Script Block Logging"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$name="EnableScriptBlockLogging"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn on PowerShell Transcription' is diabled.
write-host "[+] Disabling Turn on PowerShell Transcription"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
$name="EnableTranscripting"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow Windows Ink Workspace' is disabled.
write-host "[+] Disabling Allow Windows Ink Workspace"
$registrypath="HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace"
$name="AllowWindowsInkWorkspace"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow unencrypted traffic for WINRM Service' is disabled.
write-host "[+] Disabling Allow unencrypted traffic for WINRM Service"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
$name="AllowUnencryptedTraffic"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow unencrypted traffic for WINRM client' is disabled.
write-host "[+] Disabling Allow unencrypted traffic for WINRM client"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
$name="AllowUnencryptedTraffic"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Disallow Digest authentication' is enabled.
write-host "[+] Enabling Disallow Digest authentication"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
$name="AllowDigest"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Disallow WinRM from storing RunAs credentials' is enabled.
write-host "[+] Enabling Disallow WinRM from storing RunAs credentials"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
$name="DisableRunAs"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not delete temp folders upon exit' is disabled.
write-host "[+] Disabling Do not delete temp folders upon exit"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="DeleteTempDirsOnExit"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not use temporary folders per session' is disabled.
write-host "[+] Disabling Do not use temporary folders per session"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="PerSessionTempDir"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off picture password sign-in' is enabled.
write-host "[+] Enabling Turn off picture password sign-in"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\System"
$name="BlockDomainPicturePassword"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Use DNS name resolution when a single-label domain name is used,by appending different registere DNS suffixes,if the AllowSingleLabelDnsDomain,,,' is disabled.
write-host "[+] Disabling Use DNS name resolution when a single-label domain name is used,by appending different registere DNS suffixes"
$registrypath="HKLM:\Software\Policies\Microsoft\Netlogon\Parameters"
$name="AllowDnsSuffixSearch"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Restrict delegation of credentials to remote servers' is enabled.
write-host "[+] Enabling Restrict delegation of credentials to remote servers"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
$name="RestrictedRemoteAdministration"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Do not include drivers with Windows Updates' is enabled.
write-host "[+] Enabling Do not include drivers with Windows Updates"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
$name="ExcludeWUDriversInQualityUpdate"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Turn off auto-restart for updates during active hours' is disabled.
write-host "[+] Disabling Turn off auto-restart for updates during active hours"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
$name="SetActiveHours"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Automatically send memory dumps for OS-generated error reports' is disabled.
write-host "[+] Disabling Automatically send memory dumps for OS-generated error reports"
$registrypath="HKLM:\Software\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting"
$name="AutoApproveOSDumps"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow Cortana above lock screen' is disabled.
write-host "[+] Disabling Allow Cortana above lock screen"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
$name="AllowCortanaAboveLoc"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'System:Control Event Log behavior when the log file reaches its maximum size' is enabled. THIS ONE REQUIRES CHECK-DUPLICATE WITH DIFFERENT VALUE.
write-host "[+] Enabling System:Control Event log behavior when the log file reaches its maximum size"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\System"
$name="Retention"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Redirect only the defult client printer' is enabled.
write-host "[+] Enabling Redirect only the default client printer"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$name="RedirectOnlyDefaultClientPrinter"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow basic authentication-WINRM Client' is disabled. CHECK:we have disabled both basic and digest authentication. This is OK?
write-host "[+] Disabling Allow basic authentication-WINRM Client"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client"
$name="AllowBasic"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow basic authentication-WINRM Service' is disabled.
write-host "[+] Disabling Allow basic authentication-WINRM Service"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
$name="AllowBasic"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Only display the private store within the Windows Store App' is disabled.
write-host "[+] Disabling Only display the private store within the Windows Store App"
$registrypath="HKLM:\Software\Policies\Microsoft\WindowsStore"
$name="RequirePrivateStoreOnly"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure search suggestions in Address bar' is disabled.
write-host "[+] Disabling Configure search suggestions in Address bar"
$registrypath="HKLM:\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes"
$name="ShowSearchSuggestionsGlobal"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Allow Cortana' is disabled.
write-host "[+] Disabling Allow Cortana"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Windows Search"
$name="AllowCortana"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Configure the Commercial ID' is disabled.
write-host "[+] Disabling Configure the Commercial ID"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
$name="CommercialID"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Force specific screen saver:Screensaver executable name' is enabled:scrnsave.scr.
write-host "[+] Setting Force specific screen saver:Screensaver executable name to scrnsave.scr"
$registrypath="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$name="SCRNSAVE.EXE"
$value="scrnsave.scr"
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Prevent enabling lock screen slide show' is enabled.
write-host "[+] Enabling Prevent enabling lock screen slide show"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Personalization"
$name="NoLockScreenSlideshow"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Always install with elevated privileges' is disabled.
write-host "[+] Disabling Always install with elevated privileges"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Installer"
$name="AlwaysInstallElevated"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Screensaver Timeout' is set to 900.
write-host "[+] Setting Screensaver Timeout to 900 secs"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$name="ScreenSaveTimeOut"
$value=900
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'System:Specify the maximum log file size (KB)' is set to 32,768 
write-host "[+] Setting System:Specify the maximum log file size (KB)  to 32,768"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows\EventLog\System"
$name="MaxSize"
$value=32768
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Audit:Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is enabled. 
write-host "[+] Enabling Audit:Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="SCENoApplyLegacyAuditPolicy"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'. 
write-host "[+] Setting Accounts:Block Microsoft accounts to 'Users can't add or log on with Microsoft accounts'"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name="NoConnectedUser"
$value=3
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Microsoft network server:Amount of idle time required before suspending session' is set to 15mins. 
write-host "[+] Setting Microsoft network server: Amount of idle time required before suspending session to 15 mins"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$name="autodisconnect"
$value=15
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Microsoft network server:Digitally sign communications (if client agrees) ' is enabled. 
write-host "[+] Enabling Microsoft network server: Digitally sign communications (if client agrees)"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$name="EnableSecuritySignature"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Microsoft network server:Server SPN target name validation level' is set to 'Accept if provided by client'. 
write-host "[+] Setting Microsoft network server: Server SPN target name validation level to 'Accept if provided by client'"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$name="SmbServerNameHArdeningLevel"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is enabled. 
write-host "[+] Enabling Network access: Do not allow storage of passwords and credentials for network authentication"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="DisableDomainCreds"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators:Remote Access: Allow'. 
write-host "[+] Setting Network access: Restrict clients allowed to make remote calls to SAM to 'Administrators:Remote Access:Allow'"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="RestrictRemoteSAM"
$value="O:BAG:BAD:(A;;RC;;;BA)"
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network access: Named pipes that can be accessed anonymously' set to 'Blank/None'. 
write-host "[+] Setting Network access: Named pipes that can be accessed anonymously is set to Blank/None"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$name="NullSessionPipes"
$value=""
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is enabled. 
write-host "[+] Enabling Network access: Do not allow anonymous enumeration of SAM accounts and shares"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="RestrictAnonymous"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'. 
write-host "[+] Setting Network access: Shares that can be accessed anonymously is set to None"
$registrypath="HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$name="NullSessionShares"
$value=""
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types'. 
write-host "[+] Setting Network security: Configure encryption types allowed for Kerberos to 'RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types'"
$registrypath="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$name="SupportedEncryptionTypes"
$value=2147483644
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network security: Allow PKU2U authentication requests to this computer to use online identities' is disabled. 
write-host "[+] Disabling Network security: Allow PKU2U authentication requests to this computer to use online identities"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa\pku2u"
$name="AllowOnlineID"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'. 
write-host "[+] Setting Network security: LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM and NTLM'"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="LmCompatibilityLevel"
$value=5
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Deny logon through Remote Desktop Services' is set to at least Guests. 
write-host "[+] Setting Deny logon through Remote Desktop Services to at least Guests"
$registrypath="HKLM:\System\CurrentControlSet\Control\Terminal Server"
$name="fDenyTSConnections"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Network Security:Restrict NTLM: Audit incoming NTLM traffic' is set to 'Not defined'. 
write-host "[+] Setting Network security: Restrict NTLM: Audit incoming NTLM traffic to 'Not defined'"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
$name="AuditReceivingNTLMTraffic"
$value=2
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Audit: Audit the access of global system objects' is set to 'Enabled'. 
write-host "[+] Enabling Audit:Audit the access of global system objects"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="AuditBaseObjects"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Audit: Audit the use of Backup and Restore privilege' is set to 'Disabled'. 
write-host "[+] Disabling Audit: Audit the use of Backup and Restore privilege"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="FullPrivilegeAuditing"
$value=0
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'DCOM: Machine access restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not defined'. 
write-host "[+] Setting DCOM: Machine access restrictions in Security Descriptor Definition Language (SDDL) syntax to 'Not defined'"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\DCOM"
$name="MachineAccessRestriction"
$value=""
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'Devices: Restrict floppy access to locally logged-on user only' is set to 'Enabled'. 
write-host "[+] Enabling Devices: Restrict floppy access to locally logged-on user only"
$registrypath="HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"
$name="Allocatefloppies"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'DCOM: Machine Launch restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Not defined'. 
write-host "[+] Setting DCOM: Machine Launch restrictions in Security Descriptor Definition Language (SDDL) syntax to 'Not defined'"
$registrypath="HKLM:\Software\Policies\Microsoft\Windows NT\DCOM"
$name="MachineLaunchRestriction"
$value=""
SetRegistryHardening ($registrypath,$name,$value)

# Ensure 'LSA Protection' is set to 'Enabled'. 
write-host "[+] Enabling LSA Protection"
$registrypath="HKLM:\System\CurrentControlSet\Control\Lsa"
$name="RunAsPPL"
$value=1
SetRegistryHardening ($registrypath,$name,$value)

# Ensure Symantec Endpoint Protection Agent is installed and is at least version 12. THIS IS NOT FINISHED
# parse below command, compare displayname with Symantec Endpoint and check if ver > or equal to 12
write-host "[+] Checking version of Symantec Endpoint Protection Agent version"
$displayname=Get-ItemProperty hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\* | select-object displayname
$versionname=Get-ItemProperty hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\* | select-object displayversion

if ($displayname -like '*Symantec Endpoint*' -And $versionname -like '*12.*' -Or $versionname -like '*13.*')
{
write-host "Symantec Endpoint installed with valid version"
}
Else
{
write-host "Symantec Endpoint invalid version or not installed"
}
#Turning off Windows firewall for all profiles (Private,Public and Domain)
write-host "Setting Windows Firewall to off..."
netsh advfirewall set allprofiles state off

write-host "setting execution policy back to Restricted"
set-executionpolicy restricted


