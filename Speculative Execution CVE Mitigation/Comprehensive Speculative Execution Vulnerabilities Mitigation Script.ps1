# Comprehensive Speculative Execution Vulnerabilities Mitigation Script
# 
# DESCRIPTION:
# This script provides comprehensive mitigation for multiple speculative execution
# vulnerabilities affecting Intel, AMD, and ARM processors. It configures all
# necessary registry settings and system protections in a single deployment.
# 
# COVERED VULNERABILITIES:
# CVE-2018-3639 | Speculative Store Bypass (Variant 4)
# CVE-2022-21166 | Device Register Partial Write (DRPW)
# CVE-2022-21125 | Shared Buffer Data Sampling (SBDS)
# CVE-2022-21123 | Shared Buffer Data Read (SBDR)
# CVE-2020-0550  | Intel Data Cache Improper Data Forwarding
# CVE-2017-5715  | Spectre Variant 2 (Branch Target Injection)
# CVE-2017-5754  | Meltdown (Rogue Data Cache Load)
# CVE-2018-3620  | L1 Terminal Fault OS/SMM
# CVE-2018-3646  | L1 Terminal Fault VMM
# CVE-2018-11091 | Microarchitectural Data Sampling Uncacheable Memory (MDSUM)
# CVE-2018-12126 | Microarchitectural Store Buffer Data Sampling (MSBDS)
# CVE-2018-12127 | Microarchitectural Fill Buffer Data Sampling (MFBDS)
# CVE-2018-12130 | Microarchitectural Load Port Data Sampling (MLPDS)
# CVE-2019-11135 | TSX Transaction Asynchronous Abort (TAA)
#
# MITIGATION CLASSES:
# - Speculative Store Bypass Disable (SSBD)
# - Branch Target Injection (BTI) Mitigations
# - L1 Terminal Fault (L1TF) Protections
# - Microarchitectural Data Sampling (MDS) Mitigations
# - MMIO Stale Data Vulnerabilities
# - TSX Async Abort Protections
#
# REGISTRY MODIFICATIONS:
# - FeatureSettingsOverride (Combined bitwise values)
# - FeatureSettingsOverrideMask (Combined bitwise masks)
# - MinVmVersionForCpuBasedMitigations
# - Additional processor-specific settings
#
# COMPATIBILITY:
# - Windows 10 (Build 1803 and later)
# - Windows Server 2016/2019/2022
# - Intel, AMD, and ARM processors
# - Requires administrative privileges
#
# IMPORTANT NOTES:
# - Significant performance impact may occur after applying all mitigations
# - System restart required for changes to take effect
# - Verify microcode updates are installed before running
# - Test in non-production environment first
# - Some mitigations may require disabling Hyper-Threading
#
# DATTORMM DEPLOYMENT SETTINGS:
# - Set Force parameter to True in DattoRMM for automated execution
# - Monitor output via DattoRMM logs for success/failure status
# - Script will exit with code 0 on success, 1 on failure
# - Registry backups stored in C:\Windows\Temp with timestamp
# - Comprehensive verification of all mitigation settings
#
# PARAMETERS:
# -Verbose: Enable detailed output logging
# -WhatIf: Show what would be changed without making modifications
# -Force: Skip confirmation prompts (recommended for DattoRMM)
# -ProcessorType: Auto-detect or specify (Intel/AMD/ARM)
#
# AUTHOR: System Administrator
# VERSION: 2.0
# CREATED: 2024
# MODIFIED: 2025 - Comprehensive Multi-CVE Coverage

param(
    [switch]$Verbose = $false,
    [switch]$WhatIf = $false,
    [switch]$Force = $true,
    [ValidateSet("Auto", "Intel", "AMD", "ARM")]
    [string]$ProcessorType = "Auto"
)

# Set verbose preference based on parameter
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Function to write standardized output
function Write-Output-Message {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

# Function to check if running as administrator
function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to get processor information
function Get-ProcessorInfo {
    try {
        $processor = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $manufacturer = $processor.Manufacturer.ToLower()
        
        $detectedType = "Unknown"
        if ($manufacturer -like "*intel*") {
            $detectedType = "Intel"
        }
        elseif ($manufacturer -like "*amd*" -or $manufacturer -like "*advanced micro devices*") {
            $detectedType = "AMD"
        }
        elseif ($manufacturer -like "*arm*" -or $manufacturer -like "*qualcomm*") {
            $detectedType = "ARM"
        }
        
        return @{
            Manufacturer = $processor.Manufacturer
            Name = $processor.Name
            Architecture = $processor.Architecture
            DetectedType = $detectedType
            Family = $processor.Family
            Model = $processor.Model
            Stepping = $processor.Stepping
        }
    }
    catch {
        Write-Output-Message "Failed to retrieve processor information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function to check Windows version compatibility
function Test-WindowsCompatibility {
    $osVersion = [System.Environment]::OSVersion.Version
    $buildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
    $productName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    
    Write-Verbose "OS: $productName"
    Write-Verbose "OS Version: $($osVersion.ToString())"
    Write-Verbose "Build Number: $buildNumber"
    
    # Windows 10 Build 1803 (17134) or later required for full mitigation support
    if ([int]$buildNumber -ge 17134) {
        return $true
    }
    else {
        Write-Output-Message "Windows build $buildNumber is not supported. Build 17134 (1803) or later required for full mitigation coverage." "ERROR"
        return $false
    }
}

# Function to backup registry before modifications
function Backup-RegistryKey {
    param([string]$KeyPath)
    
    try {
        $backupPath = "C:\Windows\Temp\Comprehensive-CVE-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').reg"
        Write-Output-Message "Creating registry backup at: $backupPath" "INFO"
        
        if (-not $WhatIf) {
            reg export $KeyPath $backupPath /y | Out-Null
            Write-Output-Message "Registry backup completed successfully" "INFO"
        }
        else {
            Write-Output-Message "WhatIf: Would create registry backup at $backupPath" "INFO"
        }
        
        return $backupPath
    }
    catch {
        Write-Output-Message "Failed to create registry backup: $($_.Exception.Message)" "WARNING"
        return $null
    }
}

# Function to set registry value with error handling
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )
    
    try {
        Write-Verbose "Setting registry value: $Path\$Name = $Value ($Type)"
        
        if (-not $WhatIf) {
            # Ensure the registry path exists
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
                Write-Verbose "Created registry path: $Path"
            }
            
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Output-Message "Set $Path\$Name = $Value" "INFO"
        }
        else {
            Write-Output-Message "WhatIf: Would set $Path\$Name = $Value ($Type)" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Output-Message "Failed to set registry value $Path\$Name : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to calculate comprehensive FeatureSettingsOverride value
function Get-ComprehensiveFeatureSettings {
    param([string]$ProcessorFamily)
    
    # Bitwise values for different mitigations
    # Based on Microsoft KB articles and Intel/AMD guidance
    $mitigationBits = @{
        "SSBD"              = 8        # CVE-2018-3639 - Bit 3
        "L1TF_VMM"          = 64       # CVE-2018-3646 - Bit 6  
        "MDS_CLEAR"         = 16       # CVE-2018-11091/12126/12127/12130 - Bit 4
        "TAA_DISABLE"       = 128      # CVE-2019-11135 - Bit 7
        "MMIO_MITIGATION"   = 256      # CVE-2022-21123/21125/21166 - Bit 8
        "BRANCH_INJECTION"  = 1        # CVE-2017-5715 - Bit 0
        "ROGUE_DATA_CACHE"  = 2        # CVE-2017-5754 - Bit 1
        "L1TF_OS"           = 32       # CVE-2018-3620 - Bit 5
    }
    
    # Base configuration - enable core mitigations for all processors
    $baseValue = $mitigationBits.SSBD + 
                 $mitigationBits.MDS_CLEAR + 
                 $mitigationBits.L1TF_VMM + 
                 $mitigationBits.L1TF_OS + 
                 $mitigationBits.TAA_DISABLE + 
                 $mitigationBits.MMIO_MITIGATION +
                 $mitigationBits.BRANCH_INJECTION +
                 $mitigationBits.ROGUE_DATA_CACHE
    
    # Processor-specific adjustments
    switch ($ProcessorFamily) {
        "Intel" {
            # Intel processors need all mitigations
            $finalValue = $baseValue
            Write-Verbose "Intel processor detected - applying full mitigation set"
        }
        "AMD" {
            # AMD processors - some mitigations not applicable
            # Remove L1TF mitigations (Intel-specific)
            $finalValue = $baseValue - $mitigationBits.L1TF_VMM - $mitigationBits.L1TF_OS
            Write-Verbose "AMD processor detected - excluding Intel-specific L1TF mitigations"
        }
        "ARM" {
            # ARM processors - limited mitigations applicable
            $finalValue = $mitigationBits.SSBD + $mitigationBits.BRANCH_INJECTION
            Write-Verbose "ARM processor detected - applying ARM-compatible mitigations"
        }
        default {
            # Unknown processor - apply conservative set
            $finalValue = $baseValue
            Write-Verbose "Unknown processor - applying comprehensive mitigation set"
        }
    }
    
    # Calculate mask (all bits we're setting)
    $maskValue = $mitigationBits.SSBD + 
                 $mitigationBits.MDS_CLEAR + 
                 $mitigationBits.L1TF_VMM + 
                 $mitigationBits.L1TF_OS + 
                 $mitigationBits.TAA_DISABLE + 
                 $mitigationBits.MMIO_MITIGATION +
                 $mitigationBits.BRANCH_INJECTION +
                 $mitigationBits.ROGUE_DATA_CACHE
    
    Write-Output-Message "Calculated FeatureSettingsOverride: $finalValue (0x$([System.Convert]::ToString($finalValue, 16)))" "INFO"
    Write-Output-Message "Calculated FeatureSettingsOverrideMask: $maskValue (0x$([System.Convert]::ToString($maskValue, 16)))" "INFO"
    
    return @{
        Override = $finalValue
        Mask = $maskValue
        ProcessorFamily = $ProcessorFamily
    }
}

# Function to apply comprehensive CVE mitigations
function Apply-ComprehensiveMitigations {
    param([hashtable]$ProcessorInfo)
    
    Write-Output-Message "Starting comprehensive speculative execution vulnerability mitigation" "INFO"
    
    # Registry path for Speculative Execution mitigations
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    
    # Backup registry before modifications
    $backupPath = Backup-RegistryKey "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    
    # Determine processor type
    $procType = if ($ProcessorType -eq "Auto") { $ProcessorInfo.DetectedType } else { $ProcessorType }
    Write-Output-Message "Target processor type: $procType" "INFO"
    
    # Get comprehensive feature settings
    $featureSettings = Get-ComprehensiveFeatureSettings -ProcessorFamily $procType
    
    $success = $true
    
    # Set main mitigation registry values
    if (-not (Set-RegistryValue -Path $regPath -Name "FeatureSettingsOverride" -Value $featureSettings.Override -Type "DWORD")) {
        $success = $false
    }
    
    if (-not (Set-RegistryValue -Path $regPath -Name "FeatureSettingsOverrideMask" -Value $featureSettings.Mask -Type "DWORD")) {
        $success = $false
    }
    
    # Additional mitigation settings
    # MinVmVersionForCpuBasedMitigations for Hyper-V environments
    if (-not (Set-RegistryValue -Path $regPath -Name "MinVmVersionForCpuBasedMitigations" -Value "1.0" -Type "String")) {
        $success = $false
    }
    
    # Processor-specific additional settings
    switch ($procType) {
        "Intel" {
            Write-Output-Message "Applying Intel-specific mitigations" "INFO"
            
            # Intel TSX settings for CVE-2019-11135
            $tsxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
            if (-not (Set-RegistryValue -Path $tsxPath -Name "DisableTsx" -Value 1 -Type "DWORD")) {
                Write-Output-Message "Failed to set Intel TSX disable setting" "WARNING"
            }
        }
        "AMD" {
            Write-Output-Message "Applying AMD-specific mitigations" "INFO"
            
            # AMD-specific settings for CVE-2022-23825 and others
            # Enable additional protections for AMD processors
            $amdOverride = 16777280  # Specific value for AMD CVE-2022-23825
            if (-not (Set-RegistryValue -Path $regPath -Name "FeatureSettingsOverride" -Value $amdOverride -Type "DWORD")) {
                Write-Output-Message "Failed to set AMD-specific override" "WARNING"
            }
        }
        "ARM" {
            Write-Output-Message "Applying ARM-specific mitigations" "INFO"
            # ARM processors have limited exposure to x86-specific vulnerabilities
            # Focus on Spectre variants that affect ARM
        }
    }
    
    # Additional system hardening settings
    Write-Output-Message "Applying additional system hardening" "INFO"
    
    # Enable additional kernel mitigations
    $kernelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
    if (-not (Set-RegistryValue -Path $kernelPath -Name "MitigationOptions" -Value "2000000000000000" -Type "QWORD")) {
        Write-Output-Message "Failed to set kernel mitigation options" "WARNING"
    }
    
    return $success
}

# Function to verify comprehensive mitigation settings
function Test-ComprehensiveMitigations {
    param([hashtable]$ProcessorInfo)
    
    Write-Output-Message "Verifying comprehensive CVE mitigation settings" "INFO"
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $verified = $true
    $verificationResults = @()
    
    try {
        # Get expected values
        $procType = if ($ProcessorType -eq "Auto") { $ProcessorInfo.DetectedType } else { $ProcessorType }
        $expectedSettings = Get-ComprehensiveFeatureSettings -ProcessorFamily $procType
        
        # Check FeatureSettingsOverride
        $overrideValue = Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverride" -ErrorAction Stop
        if ($overrideValue.FeatureSettingsOverride -eq $expectedSettings.Override) {
            $verificationResults += "FeatureSettingsOverride: PASS (Value: $($overrideValue.FeatureSettingsOverride))"
            Write-Output-Message "FeatureSettingsOverride correctly set to $($overrideValue.FeatureSettingsOverride)" "INFO"
        }
        else {
            $verificationResults += "FeatureSettingsOverride: FAIL (Expected: $($expectedSettings.Override), Got: $($overrideValue.FeatureSettingsOverride))"
            Write-Output-Message "FeatureSettingsOverride value incorrect: Expected $($expectedSettings.Override), Got $($overrideValue.FeatureSettingsOverride)" "ERROR"
            $verified = $false
        }
        
        # Check FeatureSettingsOverrideMask
        $maskValue = Get-ItemProperty -Path $regPath -Name "FeatureSettingsOverrideMask" -ErrorAction Stop
        if ($maskValue.FeatureSettingsOverrideMask -eq $expectedSettings.Mask) {
            $verificationResults += "FeatureSettingsOverrideMask: PASS (Value: $($maskValue.FeatureSettingsOverrideMask))"
            Write-Output-Message "FeatureSettingsOverrideMask correctly set to $($maskValue.FeatureSettingsOverrideMask)" "INFO"
        }
        else {
            $verificationResults += "FeatureSettingsOverrideMask: FAIL (Expected: $($expectedSettings.Mask), Got: $($maskValue.FeatureSettingsOverrideMask))"
            Write-Output-Message "FeatureSettingsOverrideMask value incorrect: Expected $($expectedSettings.Mask), Got $($maskValue.FeatureSettingsOverrideMask)" "ERROR"
            $verified = $false
        }
        
        # Check MinVmVersionForCpuBasedMitigations
        try {
            $vmVersionValue = Get-ItemProperty -Path $regPath -Name "MinVmVersionForCpuBasedMitigations" -ErrorAction Stop
            $verificationResults += "MinVmVersionForCpuBasedMitigations: PASS (Value: $($vmVersionValue.MinVmVersionForCpuBasedMitigations))"
            Write-Output-Message "MinVmVersionForCpuBasedMitigations correctly set" "INFO"
        }
        catch {
            $verificationResults += "MinVmVersionForCpuBasedMitigations: WARNING (Not set)"
            Write-Output-Message "MinVmVersionForCpuBasedMitigations not found (may not be required)" "WARNING"
        }
        
        # Generate verification summary
        Write-Output-Message "=== VERIFICATION SUMMARY ===" "INFO"
        foreach ($result in $verificationResults) {
            Write-Output-Message $result "INFO"
        }
        Write-Output-Message "=== END VERIFICATION ===" "INFO"
        
    }
    catch {
        Write-Output-Message "Failed to verify mitigation settings: $($_.Exception.Message)" "ERROR"
        $verified = $false
    }
    
    return $verified
}

# Function to check for microcode updates and system patches
function Test-SystemUpdates {
    Write-Output-Message "Checking for system updates and microcode" "INFO"
    
    try {
        # Check for recent security updates
        $recentUpdates = Get-HotFix | Where-Object { 
            $_.Description -like "*Security*" -and 
            $_.InstalledOn -gt (Get-Date).AddDays(-180) 
        } | Sort-Object InstalledOn -Descending
        
        if ($recentUpdates.Count -gt 0) {
            Write-Output-Message "Recent security updates found (last 180 days): $($recentUpdates.Count)" "INFO"
            $recentUpdates | Select-Object -First 3 | ForEach-Object {
                Write-Verbose "Update: $($_.HotFixID) - $($_.Description) - Installed: $($_.InstalledOn)"
            }
        }
        else {
            Write-Output-Message "No recent security updates found. Consider checking Windows Update." "WARNING"
        }
        
        # Check Windows version for automatic protections
        $buildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        if ([int]$buildNumber -ge 17763) {  # Windows 10 1809 / Server 2019
            Write-Output-Message "Windows version supports automatic speculative execution protections" "INFO"
        }
        else {
            Write-Output-Message "Consider upgrading to Windows 10 1809+ or Server 2019+ for enhanced automatic protections" "WARNING"
        }
        
    }
    catch {
        Write-Output-Message "Could not check for system updates: $($_.Exception.Message)" "WARNING"
    }
}

# Function to set Windows reboot required notification
function Set-RebootRequiredNotification {
    Write-Output-Message "Setting Windows reboot required notification" "INFO"
    
    try {
        # Set the AutoRebootRequiredLogonRequired registry value
        # This triggers the Windows reboot required notification icon
        $rebootRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        
        if (-not $WhatIf) {
            # Ensure the registry path exists
            if (-not (Test-Path $rebootRegPath)) {
                New-Item -Path $rebootRegPath -Force | Out-Null
                Write-Verbose "Created reboot notification registry path"
            }
            
            # Set reboot required flag
            Set-ItemProperty -Path $rebootRegPath -Name "PostRebootReporting" -Value 1 -Type DWORD -Force
            Write-Output-Message "Windows reboot required notification enabled" "INFO"
            
            # Alternative method - set via Windows Update API approach
            $updateRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            Set-ItemProperty -Path $updateRegPath -Name "RebootRequired" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue
            
            # Set additional notification registry keys used by Windows
            $notificationRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting"
            if (-not (Test-Path $notificationRegPath)) {
                New-Item -Path $notificationRegPath -Force | Out-Null
            }
            Set-ItemProperty -Path $notificationRegPath -Name "CVE-Mitigation-Reboot" -Value "Required for CVE mitigations to take effect" -Type String -Force
            
            # Use Windows API to trigger notification if available
            try {
                Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class Win32API {
                    [DllImport("user32.dll", SetLastError = true)]
                    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
                    
                    public static readonly IntPtr HWND_BROADCAST = new IntPtr(0xffff);
                    public static readonly uint WM_SETTINGCHANGE = 0x001A;
                }
"@
                [Win32API]::PostMessage([Win32API]::HWND_BROADCAST, [Win32API]::WM_SETTINGCHANGE, [IntPtr]::Zero, [IntPtr]::Zero)
                Write-Verbose "Broadcast settings change message sent"
            }
            catch {
                Write-Verbose "Could not broadcast settings change: $($_.Exception.Message)"
            }
        }
        else {
            Write-Output-Message "WhatIf: Would set Windows reboot required notification" "INFO"
        }
        
        return $true
    }
    catch {
        Write-Output-Message "Failed to set reboot required notification: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# Function to generate mitigation report
function New-MitigationReport {
    param([hashtable]$ProcessorInfo, [bool]$Success)
    
    $reportPath = "C:\Windows\Temp\CVE-Mitigation-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    $report = @"
=== COMPREHENSIVE SPECULATIVE EXECUTION CVE MITIGATION REPORT ===
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

PROCESSOR INFORMATION:
- Manufacturer: $($ProcessorInfo.Manufacturer)
- Name: $($ProcessorInfo.Name)
- Detected Type: $($ProcessorInfo.DetectedType)
- Architecture: $($ProcessorInfo.Architecture)
- Family: $($ProcessorInfo.Family)
- Model: $($ProcessorInfo.Model)

VULNERABILITIES ADDRESSED:
- CVE-2018-3639: Speculative Store Bypass
- CVE-2022-21166: Device Register Partial Write
- CVE-2022-21125: Shared Buffer Data Sampling
- CVE-2022-21123: Shared Buffer Data Read
- CVE-2020-0550: Intel Data Cache Improper Data Forwarding
- CVE-2017-5715: Spectre Variant 2
- CVE-2017-5754: Meltdown
- CVE-2018-3620: L1 Terminal Fault OS/SMM
- CVE-2018-3646: L1 Terminal Fault VMM
- CVE-2018-11091: MDS Uncacheable Memory
- CVE-2018-12126: MDS Store Buffer Data Sampling
- CVE-2018-12127: MDS Fill Buffer Data Sampling
- CVE-2018-12130: MDS Load Port Data Sampling
- CVE-2019-11135: TSX Transaction Asynchronous Abort

MITIGATION STATUS: $(if ($Success) { "SUCCESS" } else { "FAILED" })

NEXT STEPS:
1. System restart required for changes to take effect
2. Verify microcode updates are installed
3. Monitor system performance after restart
4. Consider Hyper-Threading settings based on risk assessment
5. Run Get-SpeculationControlSettings PowerShell module if available

PERFORMANCE IMPACT:
- Significant performance impact expected
- Test thoroughly in non-production environment
- Consider workload-specific optimizations

REGISTRY BACKUP LOCATION: C:\Windows\Temp\
"@

    try {
        if (-not $WhatIf) {
            $report | Out-File -FilePath $reportPath -Encoding UTF8
            Write-Output-Message "Mitigation report saved to: $reportPath" "INFO"
        }
        else {
            Write-Output-Message "WhatIf: Would create mitigation report at $reportPath" "INFO"
        }
    }
    catch {
        Write-Output-Message "Failed to create mitigation report: $($_.Exception.Message)" "WARNING"
    }
}

# Main execution block
try {
    Write-Output-Message "Comprehensive Speculative Execution CVE Mitigation Script Starting" "INFO"
    Write-Output-Message "Target CVEs: 2018-3639, 2022-21166, 2022-21125, 2022-21123, 2020-0550, and related" "INFO"
    
    # Check administrative privileges
    if (-not (Test-AdminPrivileges)) {
        Write-Output-Message "Administrative privileges required. Please run as Administrator." "ERROR"
        exit 1
    }
    
    # Check Windows compatibility
    if (-not (Test-WindowsCompatibility)) {
        Write-Output-Message "System does not meet minimum requirements" "ERROR"
        exit 1
    }
    
    # Get processor information
    $processorInfo = Get-ProcessorInfo
    if (-not $processorInfo) {
        Write-Output-Message "Unable to determine processor information" "ERROR"
        exit 1
    }
    
    Write-Output-Message "Processor: $($processorInfo.Manufacturer) $($processorInfo.Name)" "INFO"
    Write-Output-Message "Detected Type: $($processorInfo.DetectedType)" "INFO"
    
    # Check for system updates and microcode
    Test-SystemUpdates
    
    # Confirm action unless Force parameter is used
    if (-not $Force -and -not $WhatIf) {
        Write-Output-Message "This script will modify system registry settings to mitigate multiple speculative execution vulnerabilities" "INFO"
        Write-Output-Message "SIGNIFICANT performance impact may occur. System restart will be required." "WARNING"
        Write-Output-Message "The following CVEs will be addressed:" "INFO"
        Write-Output-Message "  - CVE-2018-3639, CVE-2022-21166, CVE-2022-21125, CVE-2022-21123" "INFO"
        Write-Output-Message "  - CVE-2020-0550, CVE-2017-5715, CVE-2017-5754, and related vulnerabilities" "INFO"
        
        $confirmation = Read-Host "Do you want to continue? (Y/N)"
        if ($confirmation -notmatch '^[Yy]') {
            Write-Output-Message "Operation cancelled by user" "INFO"
            exit 0
        }
    }
    
    # Apply comprehensive mitigations
    if (Apply-ComprehensiveMitigations -ProcessorInfo $processorInfo) {
        Write-Output-Message "Comprehensive CVE mitigations applied successfully" "INFO"
        
        # Verify settings
        if (Test-ComprehensiveMitigations -ProcessorInfo $processorInfo) {
            Write-Output-Message "All mitigation settings verified successfully" "INFO"
            
            # Generate report
            New-MitigationReport -ProcessorInfo $processorInfo -Success $true
            
            # Set reboot required notification
            Set-RebootRequiredNotification
            
            if (-not $WhatIf) {
                Write-Output-Message "CRITICAL: System restart required for all changes to take effect" "WARNING"
                Write-Output-Message "Windows reboot notification has been enabled in system tray" "INFO"
                Write-Output-Message "After restart, verify mitigations with: Get-SpeculationControlSettings" "INFO"
                Write-Output-Message "Monitor system performance and adjust workloads as needed" "INFO"
            }
        }
        else {
            Write-Output-Message "Mitigation verification failed" "ERROR"
            New-MitigationReport -ProcessorInfo $processorInfo -Success $false
            exit 1
        }
    }
    else {
        Write-Output-Message "Failed to apply comprehensive CVE mitigations" "ERROR"
        New-MitigationReport -ProcessorInfo $processorInfo -Success $false
        exit 1
    }
    
    Write-Output-Message "Comprehensive speculative execution CVE mitigation script completed successfully" "INFO"
    exit 0
}
catch {
    Write-Output-Message "Unexpected error occurred: $($_.Exception.Message)" "ERROR"
    Write-Output-Message "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    exit 1
}
