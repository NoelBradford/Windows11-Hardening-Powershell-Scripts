# Windows 11 Hardening PowerShell Scripts

A comprehensive collection of enterprise-grade PowerShell scripts designed to fix specific CVEs and CVE groups while maintaining **Cyber Essentials compliance**. These scripts are optimized for DattoRMM deployment and enterprise environments.

## 🛡️ Repository Overview

This repository contains battle-tested PowerShell scripts that address critical security vulnerabilities in Windows environments. Each script is designed with enterprise deployment in mind, featuring robust error handling, comprehensive logging, and verification capabilities.

### 🎯 Key Features

- **CVE-Specific Remediation** - Targeted fixes for individual or groups of related vulnerabilities
- **Cyber Essentials Compliant** - All scripts align with UK Government Cyber Essentials requirements
- **DattoRMM Optimized** - Headerless execution with clean console output and proper exit codes
- **Enterprise-Grade** - Comprehensive error handling, logging, and verification
- **Processor-Aware** - Intelligent detection and processor-specific mitigations where applicable
- **Automated Notifications** - Built-in reboot notifications and system status updates

## 📋 Available Scripts

### Speculative Execution Vulnerabilities

#### 🔧 [Comprehensive Speculative Execution CVE Mitigation](./Comprehensive-CVE-Mitigation.ps1)
**Status**: ✅ Available  
**CVEs Covered**: 14 vulnerabilities  
**Cyber Essentials**: ✅ Compliant

Addresses multiple speculative execution vulnerabilities in a single deployment:
- **CVE-2018-3639** - Speculative Store Bypass (Variant 4)
- **CVE-2022-21166** - Device Register Partial Write (DRPW)
- **CVE-2022-21125** - Shared Buffer Data Sampling (SBDS)
- **CVE-2022-21123** - Shared Buffer Data Read (SBDR)
- **CVE-2020-0550** - Intel Data Cache Improper Data Forwarding
- **CVE-2017-5715** - Spectre Variant 2 (Branch Target Injection)
- **CVE-2017-5754** - Meltdown (Rogue Data Cache Load)
- **CVE-2018-3620** - L1 Terminal Fault OS/SMM
- **CVE-2018-3646** - L1 Terminal Fault VMM
- **CVE-2018-11091** - MDS Uncacheable Memory (MDSUM)
- **CVE-2018-12126** - MDS Store Buffer Data Sampling (MSBDS)
- **CVE-2018-12127** - MDS Fill Buffer Data Sampling (MFBDS)
- **CVE-2018-12130** - MDS Load Port Data Sampling (MLPDS)
- **CVE-2019-11135** - TSX Transaction Asynchronous Abort (TAA)

**Features**: Processor-specific mitigations, comprehensive verification, automatic reboot notifications

---

### 🚧 Planned Scripts

The following scripts are planned for future releases:

#### Network Security
- **SMB Vulnerability Fixes** - CVE-2017-0143, CVE-2017-0144, CVE-2017-0145 (EternalBlue family)
- **DNS Security Hardening** - CVE-2020-1350 (SIGRed) and related DNS vulnerabilities
- **RDP Security Mitigations** - CVE-2019-0708 (BlueKeep) and RDP-related CVEs

#### Authentication & Privilege Escalation
- **NTLM Relay Mitigations** - Multiple CVEs related to NTLM authentication
- **Local Privilege Escalation Fixes** - Windows kernel and service vulnerabilities
- **Kerberos Security Hardening** - CVEs affecting Kerberos authentication

#### Application Security
- **Microsoft Office Security** - Macro and document-based vulnerability mitigations
- **Internet Explorer/Edge Fixes** - Browser-based CVE remediation
- **Print Spooler Hardening** - PrintNightmare and related printing service CVEs

#### System Hardening
- **Windows Defender Configuration** - Security baseline implementation
- **Registry Security Hardening** - Additional registry-based security improvements
- **Service Hardening Scripts** - Disable unnecessary services and secure configurations

## 🏆 Cyber Essentials Compliance

All scripts in this repository are designed to meet or exceed **UK Government Cyber Essentials** requirements:

### ✅ Technical Controls Addressed

- **Boundary Firewalls & Internet Gateways** - Network security hardening scripts
- **Secure Configuration** - System hardening and configuration management
- **Access Control** - Authentication and authorization improvements  
- **Malware Protection** - Enhanced security controls and monitoring
- **Patch Management** - Automated CVE remediation and system updates

### 📊 Compliance Features

- **Detailed Logging** - Complete audit trails for compliance reporting
- **Verification Reports** - Automated validation of applied security controls
- **Rollback Capability** - Registry backups and configuration restoration
- **Documentation** - Comprehensive documentation for audit purposes

## 🚀 Quick Start

### Prerequisites
- Windows 10 Build 1803+ or Windows Server 2016+
- PowerShell 5.1 or later
- Administrative privileges
- Latest Windows security updates (recommended)

### Basic Usage
```powershell
# Download and execute a script
.\Script-Name.ps1

# Preview changes without applying (recommended for testing)
.\Script-Name.ps1 -WhatIf

# Enable verbose logging
.\Script-Name.ps1 -Verbose

# DattoRMM deployment (automated execution)
.\Script-Name.ps1 -Force
```

### DattoRMM Deployment
1. Upload script to DattoRMM platform
2. Set execution policy: `PowerShell.exe -ExecutionPolicy Bypass`
3. Configure monitoring for exit codes (0 = success, 1 = failure)
4. Review execution logs for detailed results

## 📋 Script Standards

All scripts in this repository follow enterprise standards:

### 🔧 Technical Standards
- **Headerless Execution** - Compatible with RMM systems
- **Clean Console Output** - No emojis or special characters that interfere with RMM logging
- **Proper Exit Codes** - 0 for success, 1 for failure
- **Comprehensive Error Handling** - Graceful failure with detailed error messages
- **Registry Backups** - Automatic backup before modifications

### 📝 Documentation Standards
- **Embedded Documentation** - All documentation maintained within script files
- **CVE Cross-References** - Clear mapping to specific vulnerability identifiers
- **Parameter Documentation** - Complete parameter descriptions and usage examples
- **Compatibility Matrix** - Operating system and processor compatibility information

### 🛡️ Security Standards
- **Verification Procedures** - All scripts verify applied changes
- **Rollback Capability** - Ability to restore previous configurations
- **Least Privilege** - Scripts request only necessary permissions
- **Audit Logging** - Complete logging of all actions and changes

## 📊 Repository Structure

```
Windows11-Hardening-Powershell-Scripts/
├── README.md                           # This file
├── docs/                              # Additional documentation
│   ├── cyber-essentials-compliance.md # Detailed compliance mapping
│   ├── deployment-guide.md            # Enterprise deployment guide
│   └── troubleshooting.md             # Common issues and solutions
├── scripts/
│   ├── speculative-execution/         # Speculative execution CVE fixes
│   │   └── Comprehensive-CVE-Mitigation.ps1
│   ├── network-security/              # Network-related CVE fixes
│   ├── authentication/                # Auth and privilege CVE fixes
│   ├── application-security/          # Application CVE fixes
│   └── system-hardening/              # General hardening scripts
└── templates/                         # Script templates and examples
    ├── script-template.ps1            # Standard script template
    └── readme-template.md             # Standard README template
```

## 🔍 Testing & Validation

### Pre-Deployment Testing
1. **Laboratory Environment** - Test all scripts in isolated lab environment
2. **Compatibility Validation** - Verify compatibility with target Windows versions
3. **Performance Impact Assessment** - Measure performance impact of security controls
4. **Rollback Testing** - Validate rollback procedures work correctly

### Production Deployment
1. **Pilot Group** - Deploy to small pilot group first
2. **Monitoring** - Monitor system performance and stability
3. **Gradual Rollout** - Expand deployment gradually across environment
4. **Documentation** - Document all deployments for compliance records

## 🛠️ Contributing

We welcome contributions that align with our enterprise security focus:

### Contribution Guidelines
- **CVE Focus** - Scripts must address specific CVEs or CVE groups
- **Enterprise Quality** - Must meet enterprise deployment standards
- **Cyber Essentials Alignment** - Must support Cyber Essentials compliance
- **Complete Documentation** - Include comprehensive documentation and testing

### Submission Process
1. Fork the repository
2. Create feature branch for your CVE fix
3. Follow existing script standards and templates
4. Include comprehensive testing and documentation
5. Submit pull request with detailed description

## 📚 Resources & References

### Microsoft Security Resources
- [Microsoft Security Response Center](https://msrc.microsoft.com/)
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [Security Update Guide](https://msrc.microsoft.com/update-guide/)

### Cyber Essentials Resources
- [NCSC Cyber Essentials](https://www.ncsc.gov.uk/cyberessentials/overview)
- [Cyber Essentials Requirements](https://www.ncsc.gov.uk/files/Cyber-Essentials-Requirements-for-IT-infrastructure-2-1.pdf)
- [Implementation Guidance](https://www.ncsc.gov.uk/collection/cyber-essentials)

### CVE Databases
- [MITRE CVE Database](https://cve.mitre.org/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## 📄 License

This repository is provided for educational and enterprise security purposes. All scripts are provided as-is with no warranty. Test thoroughly in non-production environments before deploying to production systems.

## ⚠️ Important Notices

### Security Considerations
- **Test Before Production** - Always test scripts in non-production environments
- **Performance Impact** - Security mitigations may impact system performance
- **Backup Requirements** - Ensure proper backups before applying security changes
- **Monitoring** - Implement monitoring to detect issues after deployment

### Legal Compliance
- Scripts designed to support Cyber Essentials compliance
- Additional compliance requirements may apply in your environment
- Consult with security and compliance teams before deployment
- Maintain audit trails for compliance reporting

---

**🔒 Security First**: This repository prioritizes security effectiveness while maintaining system stability and compliance requirements. All scripts undergo rigorous testing and validation before release.

**📞 Support**: For enterprise support or custom CVE remediation scripts, please open an issue with detailed requirements and environment specifications.
