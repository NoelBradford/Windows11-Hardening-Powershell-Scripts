# Comprehensive Speculative Execution CVE Mitigation Script

A PowerShell script designed for enterprise deployment that provides comprehensive mitigation for multiple speculative execution vulnerabilities affecting Intel, AMD, and ARM processors.

## 🚨 Overview

This script addresses **14 critical CVEs** in a single deployment, applying processor-specific mitigations and comprehensive system hardening. Designed for DattoRMM and enterprise environments with robust error handling, verification, and reporting capabilities.

## 🛡️ Covered Vulnerabilities

### Primary Target CVEs
- **CVE-2018-3639** - Speculative Store Bypass (Variant 4)
- **CVE-2022-21166** - Device Register Partial Write (DRPW)
- **CVE-2022-21125** - Shared Buffer Data Sampling (SBDS)
- **CVE-2022-21123** - Shared Buffer Data Read (SBDR)
- **CVE-2020-0550** - Intel Data Cache Improper Data Forwarding

### Additional Mitigated CVEs
- **CVE-2017-5715** - Spectre Variant 2 (Branch Target Injection)
- **CVE-2017-5754** - Meltdown (Rogue Data Cache Load)
- **CVE-2018-3620** - L1 Terminal Fault OS/SMM
- **CVE-2018-3646** - L1 Terminal Fault VMM
- **CVE-2018-11091** - Microarchitectural Data Sampling Uncacheable Memory (MDSUM)
- **CVE-2018-12126** - Microarchitectural Store Buffer Data Sampling (MSBDS)
- **CVE-2018-12127** - Microarchitectural Fill Buffer Data Sampling (MFBDS)
- **CVE-2018-12130** - Microarchitectural Load Port Data Sampling (MLPDS)
- **CVE-2019-11135** - TSX Transaction Asynchronous Abort (TAA)

## 🎯 Key Features

### Intelligent Processor Detection
- **Auto-detects** Intel, AMD, and ARM processors
- **Applies processor-specific** mitigations
- **Excludes non-applicable** vulnerabilities (e.g., L1TF for AMD)

### Comprehensive Registry Configuration
- **Combined bitwise calculations** for optimal mitigation coverage
- **Proper mask values** ensuring all protections are active
- **Additional kernel hardening** settings

### Enterprise-Grade Verification
- **Complete validation** of all applied settings
- **Detailed verification reports** with pass/fail status
- **Processor-specific validation** based on detected hardware

### DattoRMM Optimized
- **Headerless execution** ready for RMM deployment
- **Verbose console output** with timestamp logging
- **Exit codes** for automated monitoring (0 = success, 1 = failure)
- **No emoji** characters that can interfere with RMM systems

### Advanced Notifications
- **Sets Windows reboot required** system tray notification
- **Registry-based alerts** using Windows Update notification system
- **Persistent reminders** until system restart

## 📋 System Requirements

### Operating System
- Windows 10 Build 1803 (17134) or later
- Windows Server 2016/2019/2022
- Administrative privileges required

### Processor Support
- Intel Core and Xeon processors
- AMD processors (with architecture-specific mitigations)
- ARM processors (limited mitigation set)

### Prerequisites
- Latest Windows security updates installed
- Processor microcode updates (recommended)
- Registry backup capability

## 🚀 Usage

### Basic Execution
```powershell
# Run with default settings (Force enabled for automated deployment)
.\Comprehensive-CVE-Mitigation.ps1
```

### Advanced Parameters
```powershell
# Test mode - preview changes without applying
.\Comprehensive-CVE-Mitigation.ps1 -WhatIf

# Verbose logging for detailed output
.\Comprehensive-CVE-Mitigation.ps1 -Verbose

# Specify processor type (overrides auto-detection)
.\Comprehensive-CVE-Mitigation.ps1 -ProcessorType Intel

# Interactive mode with confirmation prompts
.\Comprehensive-CVE-Mitigation.ps1 -Force:$false
```

### DattoRMM Deployment
1. Upload script to DattoRMM
2. Set execution policy: `PowerShell.exe -ExecutionPolicy Bypass`
3. Monitor exit codes for deployment status
4. Review logs for detailed execution results

## ⚙️ Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Verbose` | Switch | `$false` | Enable detailed console output and logging |
| `-WhatIf` | Switch | `$false` | Preview changes without making modifications |
| `-Force` | Switch | `$true` | Skip confirmation prompts (recommended for RMM) |
| `-ProcessorType` | String | `"Auto"` | Override processor detection (`Auto`, `Intel`, `AMD`, `ARM`) |

## 🔧 How It Works

### 1. System Validation
- Checks administrative privileges
- Validates Windows version compatibility
- Detects processor type and capabilities

### 2. Registry Backup
- Creates timestamped registry backup
- Stored in `C:\Windows\Temp\`
- Enables rollback if needed

### 3. Mitigation Application
- Calculates processor-specific registry values
- Applies comprehensive `FeatureSettingsOverride` settings
- Configures additional kernel protection settings

### 4. Verification & Reporting
- Validates all applied settings
- Generates detailed verification report
- Sets reboot required notifications

## 📊 Registry Modifications

The script modifies the following registry locations:

### Primary Mitigation Path
```
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
├── FeatureSettingsOverride (DWORD)
├── FeatureSettingsOverrideMask (DWORD)
└── MinVmVersionForCpuBasedMitigations (String)
```

### Additional Hardening
```
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel
├── DisableTsx (DWORD) - Intel specific
├── MitigationOptions (QWORD)
```

### Reboot Notifications
```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired
└── PostRebootReporting (DWORD)
```

## 📈 Performance Impact

### Expected Impact
- **Significant performance reduction** possible (5-30% depending on workload)
- **Memory-intensive applications** most affected
- **Virtualization workloads** may see higher impact

### Mitigation Strategies
- Test in non-production environment first
- Monitor application performance post-deployment
- Consider workload-specific optimizations
- Evaluate Hyper-Threading settings based on risk assessment

## 🔒 Security Considerations

### Mitigation Effectiveness
- **Complete protection** against covered vulnerabilities
- **Defense in depth** approach with multiple mitigation layers
- **Processor-specific optimizations** for maximum effectiveness

### Risk Assessment
- **High-security environments**: Deploy immediately
- **Performance-critical systems**: Test thoroughly before production deployment
- **Legacy systems**: Verify compatibility and consider upgrade paths

## 📋 Output and Logging

### Console Output Format
```
[2025-06-18 10:30:15] [INFO] Comprehensive Speculative Execution CVE Mitigation Script Starting
[2025-06-18 10:30:15] [INFO] Processor: Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz
[2025-06-18 10:30:16] [INFO] Calculated FeatureSettingsOverride: 495 (0x1ef)
[2025-06-18 10:30:16] [INFO] Set HKLM:\SYSTEM\...\Memory Management\FeatureSettingsOverride = 495
```

### Generated Files
- **Registry Backup**: `C:\Windows\Temp\Comprehensive-CVE-backup-YYYYMMDD-HHMMSS.reg`
- **Mitigation Report**: `C:\Windows\Temp\CVE-Mitigation-Report-YYYYMMDD-HHMMSS.txt`

## 🚨 Important Notes

### Critical Requirements
1. **System restart required** for all mitigations to take effect
2. **Registry backup** created automatically before modifications
3. **Microcode updates** should be installed for optimal protection
4. **Test in non-production** environment before widespread deployment

### Post-Deployment Verification
```powershell
# Check mitigation status (if SpeculationControl module available)
Get-SpeculationControlSettings

# Verify registry settings manually
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
```

## 🛠️ Troubleshooting

### Common Issues
| Issue | Cause | Solution |
|-------|-------|----------|
| "Administrative privileges required" | Script not run as Administrator | Run PowerShell as Administrator |
| "Windows build not supported" | Windows version too old | Upgrade to Windows 10 1803+ or Server 2016+ |
| "Failed to set registry value" | Registry permissions or corruption | Check registry permissions, run SFC scan |
| Verification fails | Incorrect processor detection | Use `-ProcessorType` parameter to override |

### Exit Codes
- **0**: Success - All mitigations applied and verified
- **1**: Failure - Critical error occurred during execution

### Support Information
- Review generated mitigation report for detailed status
- Check Windows Event Log for additional error information
- Verify processor microcode updates are current

## 📚 References

### Microsoft Security Advisories
- [ADV180002](https://msrc.microsoft.com/update-guide/vulnerability/ADV180002) - Speculative Execution Side Channel
- [ADV190013](https://msrc.microsoft.com/update-guide/vulnerability/ADV190013) - Microarchitectural Data Sampling
- [ADV220002](https://msrc.microsoft.com/update-guide/vulnerability/ADV220002) - Intel Processor MMIO Stale Data

### Knowledge Base Articles
- [KB4072698](https://support.microsoft.com/help/4072698) - Windows Server Guidance
- [KB4073119](https://support.microsoft.com/help/4073119) - Windows Client Guidance
- [KB4457951](https://support.microsoft.com/help/4457951) - Speculative Execution Vulnerabilities

### Processor Documentation
- [Intel Security Center](https://www.intel.com/content/www/us/en/security-center/default.html)
- [AMD Security Updates](https://www.amd.com/en/corporate/product-security)

## 📄 License

This script is provided as-is for educational and enterprise security purposes. Test thoroughly before production deployment.

## 🔄 Version History

- **v2.0** - Comprehensive multi-CVE coverage with processor-specific mitigations
- **v1.1** - DattoRMM optimization and reboot notifications  
- **v1.0** - Initial CVE-2018-3639 mitigation

---

**⚠️ Critical Reminder**: Always test security mitigations in a non-production environment before deploying to production systems. Performance impact can be significant depending on workload characteristics.
