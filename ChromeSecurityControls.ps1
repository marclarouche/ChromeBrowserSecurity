#######################################################################################################################################
##   Windows Chrome Browser Security  Implementation Script #
##   Use this script to implement the Chrome Browser security controls. A report is created upon completion. 
##   The report is located in C:\Program Files\SecurityControls\
##   Make sure to run a backup of the registry prior to running this security script.
##   Authored by Marc Larouche. April 28th 2022 : 
#######################################################################################################################################
#
#  Chrome Browser Security Tool
#  Controls obtained from DISA STIG Release 5, Benchmark Jan 27, 2022 Public Release 
#  DISA STIG checklist used to create this security script to enable browser compliance with NIST 800-53 controls
#  Chrome Browser Security Controls Script 
#  Author: Marc Larouche
#  Website: https://www.marclarouche.com/
#
#  $Script_Version = '1.0.0'
#  $Script_Date = 'April-28-2022'
#  $Release_Type = 'Stable'
#
########################################################################################################################################

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!                                         !!
# !!                 CAUTION                 !!
# !!       DO NOT EDIT PAST THIS POINT       !!
# !!    UNLESS YOU KNOW WHAT YOU ARE DOING   !!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#########################################################################################################################################
# Self-elevate if not already elevated.

if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
    "Running elevated; good."
    ""
    }
else {
    "Not running as elevated. Starting elevated shell."
    Start-Process powershell -WorkingDirectory $PSScriptRoot -Verb runAs -ArgumentList "-noprofile -noexit -file $PSCommandPath"
    return "Done. This one will now exit."
    ""
    }

#########################################################################################################################################
# Check and make a new directory in C:\Program Files\SecurityControls\ if needed

$path = "C:\Program Files\SecurityControls"
if(!(test-path $path))
{
	new-item -itemType Directory -Force -Path $path
}
#########################################################################################################################################

#########################################################################################################################################
## Set variables for log files.

$date = get-date -Format MM-dd-y
$server = $(Get-WmiObject Win32_Computersystem).name
$logpath = "C:\Program Files\SecurityControls\"
$Configurationlog = $logpath+$server+"_Chrome_Security_$date.txt"
$line = "#######################################################################################################################"

##########################################################################################################################################

##########################################################################################################################################
# Functions to checkpath
##########################################################################################################################################

Function checkPathDWORD{
Param ($registryPath, $Name, $Value)
IF(!(Test-Path $registryPath))
  {
      New-Item -Path $registryPath -Force | Out-Null
      New-ItemProperty -Path $registryPath -Name $name -Value $value `
      -PropertyType DWORD -Force | Out-Null}

 ELSE {
     New-ItemProperty -Path $registryPath -Name $name -Value $value `
     -PropertyType DWORD -Force | Out-Null}
}

##########################################################################################################################################
Function checkPathSTRING{
Param ($registryPath, $Name, $Value)
IF(!(Test-Path $registryPath))
  {
      New-Item -Path $registryPath -Force | Out-Null
      New-ItemProperty -Path $registryPath -Name $name -Value $value `
      -PropertyType STRING -Force | Out-Null}

 ELSE {
     New-ItemProperty -Path $registryPath -Name $name -Value $value `
     -PropertyType STRING -Force | Out-Null}
}
#########################################################################################################################################
# Functions to Checkpath
#########################################################################################################################################

####################################################################################################
## Firewall traversal from remote host must be disabled.
## Vul ID: V-221558 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘RemoteAccessHostFirewallTraversal’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221558 CAT II, RemoteAccessHostFirewallTraversal Reg key must = 0 $line" 

####################################################################################################
## Site tracking users location must be disabled. DefaultGeolocationSetting
## Vul ID: V-221559	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultGeolocationSetting’ -Value '2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221559 CAT II, DefaultGeolocationSetting Reg key must = 2 $line" 

####################################################################################################
## Site tracking users location must be disabled. DefaultPopupsSetting
## Vul ID: V-221561	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultPopupSetting’ -Value '2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221561 CAT II, DefaultPopupSetting Reg key must = 2 $line" 

####################################################################################################
## Extensions installation must be blacklisted by default. ExtensionInstallBlocklist
## Vul ID: V-221562

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist’ -Name ‘1’ -Value '*'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221562 CAT II, ExtensionInstallBlocklist Reg key 1 must = *.  $line" 

####################################################################################################
##  Extensions that are approved for use must be allowlisted.. ExtensionInstallAllowlist
## Vul ID: V-221563

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist’ -Name ‘1’ -Value 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist’ -Name ‘2’ -Value 'gcbommkclmclpchllfjekcdonpmejbdp'
checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist’ -Name ‘3’ -Value 'lblebdecfhdegbeoejplcpmhibbkbkin'
checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist’ -Name ‘4’ -Value 'hdokiejnpimakedhajhdlcegeplioahd'
Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221562 CAT II, ExtensionInstallAllowlist Reg key 1 must = have defined IDs.  $line" 

####################################################################################################
## The default search providers name must be set. Examples, Google, Bing, Yahoo etc. 
## Vul ID: V-221564

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultSearchProviderName’ -Value 'Google Encrypted'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221564 CAT II, DefaultSearchProviderName Reg key 1 must = *.  $line" 

####################################################################################################
## The default search provider URL must be set to perform encrypted searches.
## Vul ID: V-221565

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultSearchProviderSearchURL’ -Value 'https://www.google.com/search?q='

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221565 CAT II, DefaultSearchProviderSearchURL Reg key 1 must = An encrypted search engine.  $line" 

####################################################################################################
## Default search provider must be enabled.
## Vul ID: V-221566	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultSearchProviderEnabled’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221566 CAT II, DefaultSearchProviderEnabled Reg key must = 1 $line" 

####################################################################################################
## The Password Manager must be disabled. I leave this enabled (1) as I use LastPass password manager
## Vul ID: V-221567	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘PasswordManagerEnabled’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221567 CAT II, PasswordManagerEnabled Reg key must = 0 $line" 

####################################################################################################
## Background processing must be disabled. BackgroundModeEnabled
## Vul ID: V-221570	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘BackgroundModeEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221570 CAT II, BackgroundModeEnabled Reg key must = 0 $line" 


####################################################################################################
## Google Data Synchronization must be disabled. SyncDisabled
## Vul ID: V-221571	 CAT II

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SyncDisabled’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221571 CAT II, SyncDisabled Reg key must = 1 $line" 

####################################################################################################
## The URL protocol schema javascript must be disabled. URLBlocklist
## Vul ID: V-221572

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\URLBlocklist’ -Name ‘1’ -Value 'javascript://*'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221572 CAT II, URLBlocklist Reg key 1 must = javascript://*.  $line" 

###################################################################################################
## Cloud print sharing must be disabled. CloudPrintProxyEnabled
## Vul ID: V-221573	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘CloudPrintProxyEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221573 CAT II, CloudPrintProxyEnabled Reg key must = 0 $line" 


####################################################################################################
## Network prediction must be disabled. NetworkPredictionOptions
## Vul ID: V-221574

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘NetworkPredictionOptions’ -Value '2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221574 CAT II, NetworkPredictionOptions Reg key must = 2 $line" 

####################################################################################################
##  Metrics reporting to Google must be disabled. MetricsReportingEnabled
## Vul ID: V-221575	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘MetricsReportingEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221575 CAT II, MetricsReportingEnabled Reg key must = 0 $line" 

####################################################################################################
##  Search suggestions must be disabled. SearchSuggestEnabled
## Vul ID: V-221576

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SearchSuggestEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221576 CAT II, SearchSuggestEnabled Reg key must = 0 $line" 

####################################################################################################
## Importing of saved passwords must be disabled. ImportSavedPasswords
## Vul ID: V-221577	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘ImportSavedPasswords’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221577 CAT II, ImportSavedPasswords Reg key must = 0 $line" 

####################################################################################################
##  Incognito mode must be disabled. IncognitoModeAvailability. I have it set to available (0)
## Vul ID: V-221578	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘IncognitoModeAvailability’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221578 CAT II, IncognitoModeAvailability Reg key must = 1 $line" 

####################################################################################################
## Online revocation checks must be performed. EnableOnlineRevocationChecks
## Vul ID: V-221579 

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘EnableOnlineRevocationChecks’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221579 CAT II, EnableOnlineRevocationChecks Reg key must = 1 $line" 

####################################################################################################
## Safe Browsing must be enabled. SafeBrowsingProtectionLevel, can be set to 1 or 2 for compliance.
## Vul ID: V-221580

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SafeBrowsingProtectionLevel’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221580 CAT II, SafeBrowsingProtectionLevel Reg key must = 1 $line" 

####################################################################################################
## Browser history must be saved. SavingBrowserHistoryDisabled. I chose to delete history
## Vul ID: V-221581

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SafeBrowsingProtectionLevel’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221581 CAT II, SavingBrowserHistoryDisabled Reg key must = 0 $line"


####################################################################################################
## The version of Google Chrome running on the system must be a supported version.
## Vul ID: V-221584 Check for latest release and ensure Chrome is updated.

Start-Process -FilePath "GoogleUpdate.exe" -WorkingDirectory "C:\Program Files (x86)\Google\Update"

get-process -name Chrome | stop-process

####################################################################################################
## Deletion of browser history must be disabled. AllowDeletingBrowserHistory
## Vul ID: V-221586	I have it set to 1 as I wish to clear history after each session

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘AllowDeletingBrowserHistory’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221586 CAT II, AllowDeletingBrowserHistory Reg key must = 0 $line"

####################################################################################################
##  Prompt for download location must be enabled. PromptForDownloadLocation
##  Vul ID: V-221587	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘PromptForDownloadLocation’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221587 CAT II, PromptForDownloadLocation Reg key must = 1 $line"

####################################################################################################
##  Download restrictions must be configured. DownloadRestrictions
##  Vul ID: V-221588 Can be set to 1 or 2

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DownloadRestrictions’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221588 CAT II, DownloadRestrictions Reg key must = 1 $line"

####################################################################################################
##  Safe Browsing Extended Reporting must be disabled. SafeBrowsingExtendedReportingEnabled
##  Vul ID: V-221590	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SafeBrowsingExtendedReportingEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221590 CAT II, SafeBrowsingExtendedReportingEnabled Reg key must = 0 $line"

####################################################################################################
##  WebUSB must be disabled. DefaultWebUsbGuardSetting
##  Vul ID: V-221591

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultWebUsbGuardSetting’ -Value '2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221591 CAT II, DefaultWebUsbGuardSetting Reg key must = 2 $line"

####################################################################################################
##  Chrome Cleanup must be disabled. ChromeCleanupEnabled
##  Vul ID: V-221592 I have this set to 1 enabled to cleanup upon browser exit.

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘ChromeCleanupEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221592 CAT II, ChromeCleanupEnabled Reg key must = 0 $line"

####################################################################################################
##   Chrome Cleanup reporting must be disabled. ChromeCleanupReportingEnabled
##   Vul ID: V-221593

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘ChromeCleanupReportingEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221593 CAT II, ChromeCleanupReportingEnabled Reg key must = 0 $line"

####################################################################################################
##  Google Cast must be disabled. EnableMediaRouter
##  Vul ID: V-221594

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘EnableMediaRouter’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221594 CAT II, EnableMediaRouter Reg key must = 0 $line"

####################################################################################################
##  Autoplay must be disabled. AutoplayAllowed
##  Vul ID: V-221595

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘AutoplayAllowed’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221595 CAT II, AutoplayAllowed Reg key must = 0 $line"

####################################################################################################
##  URLs must be allowlisted for Autoplay use. AutoplayAllowlist
##  Vul ID: V-221596

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘AutoplayAllowlist’ -Value '[*.]mil,[*.]gov'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221596 CAT II, AutoplayAllowlist should = .mil & .gov.  $line"

####################################################################################################
##  Anonymized data collection must be disabled. UrlKeyedAnonymizedDataCollectionEnabled
##  Vul ID: V-221597

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘UrlKeyedAnonymizedDataCollectionEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221597 CAT II, UrlKeyedAnonymizedDataCollectionEnabled Reg key must = 0 $line"


####################################################################################################
##  Collection of WebRTC event logs must be disabled. WebRtcEventLogCollectionAllowed
##  Vul ID: V-221598

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘WebRtcEventLogCollectionAllowed’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221598 CAT II, WebRtcEventLogCollectionAllowed Reg key must = 0 $line"

####################################################################################################
##  Chrome development tools must be disabled. DeveloperToolsAvailability
##  Vul ID: V-221599 I have it set so I can use the dev tools in Chrome

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DeveloperToolsAvailability’ -Value '1'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221599 CAT II, DeveloperToolsAvailability Reg key must = 2 $line"

####################################################################################################
##  Guest Mode must be disabled. BrowserGuestModeEnabled
##  Vul ID: V-226401

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘BrowserGuestModeEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221401 CAT II, BrowserGuestModeEnabled Reg key must = 0 $line"

####################################################################################################
##  AutoFill for credit cards must be disabled. AutofillCreditCardEnabled
##  Vul ID: V-226402

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘AutofillCreditCardEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221402 CAT II, AutofillCreditCardEnabled Reg key must = 0 $line"

####################################################################################################
##   AutoFill for addresses must be disabled. AutofillAddressEnabled
##   Vul ID: V-226403

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘AutofillAddressEnabled’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221403 CAT II, AutofillAddressEnabled Reg key must = 0 $line"

####################################################################################################
##  Import AutoFill form data must be disabled. ImportAutofillFormData
##  Vul ID: V-226404

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘ImportAutofillFormData’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-221404 CAT II, ImportAutofillFormData Reg key must = 0 $line"

####################################################################################################
##  Chrome must be configured to allow only TLS. SSLVersionMin
##  Vul ID: V-234701

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘SSLVersionMin’ -Value 'tls1.2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-234701 CAT I, SSLVersionMin Reg key 1 must = tls1.2  $line" 

####################################################################################################
##  Web Bluetooth API must be disabled. DefaultWebBluetoothGuardSetting
##  Vul ID: V-241787	

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘DefaultWebBluetoothGuardSetting’ -Value '2'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-241787 CAT II, DefaultWebBluetoothGuardSetting Reg key must = 2 $line"

####################################################################################################
##  Use of the QUIC protocol must be disabled. QuicAllowed
##  Vul ID: V-245538

checkPathDWORD -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘QuicAllowed’ -Value '0'

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-245538 CAT II, QuicAllowed Reg key must = 0 $line"

####################################################################################################

## Session only based cookies must be disabled.
## Vul ID: V-245539 CAT II

checkPathSTRING -registryPath ‘HKLM:\Software\Policies\Google\Chrome\’ -Name ‘CookiesSessionOnlyForUrls’ -Value ""

Get-ItemProperty -Path 'HKLM:\Software\Policies\Google\Chrome\' | out-file $Configurationlog -Append

Add-Content $Configurationlog "Vul ID: V-245539 CAT II, CookiesSessionOnlyForUrls reg key must be NULL. $line" 

####################################################################################################
####################################################################################################


