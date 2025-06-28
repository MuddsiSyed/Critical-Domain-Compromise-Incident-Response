# Critical Domain Compromise Incident Response

[![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Incident%20Response-red?style=for-the-badge&logo=shield)](https://github.com/yourusername/Critical-Domain-Compromise-Incident-Response)
[![AWS](https://img.shields.io/badge/AWS-Security%20Groups-orange?style=for-the-badge&logo=amazon-aws)](https://aws.amazon.com/)
[![Splunk](https://img.shields.io/badge/Splunk-SIEM%20Analysis-blue?style=for-the-badge&logo=splunk)](https://www.splunk.com/)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-Domain%20Security-green?style=for-the-badge&logo=microsoft)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/)
[![Digital Forensics](https://img.shields.io/badge/Digital%20Forensics-Incident%20Analysis-purple?style=for-the-badge&logo=forensics)](https://github.com/yourusername/Critical-Domain-Compromise-Incident-Response)

**A comprehensive incident response investigation of an external threat actor achieving complete Active Directory domain compromise through ANONYMOUS LOGON exploitation and AWS Security Group misconfiguration.**

---

## 🎯 Executive Summary

External threat actor **186.10.23.226** successfully exploited misconfigured AWS Security Groups to achieve complete Active Directory domain compromise, including privilege escalation to Domain Admin and Kerberos infrastructure takeover via krbtgt account manipulation. This repository documents the complete incident response process from detection through forensic analysis and containment.

### 🚨 Critical Impact Metrics
- **36,822** failed authentication attempts over 24 hours
- **109** successful ANONYMOUS LOGON sessions  
- **Complete domain administrative access** achieved by external attacker
- **Kerberos infrastructure compromise** enabling Golden Ticket attacks
- **Advanced persistent threat** established in domain environment

### ⚡ Response Outcome
- **Attack terminated** within 2 hours of discovery
- **Complete forensic analysis** with timeline reconstruction
- **Zero data exfiltration** confirmed through comprehensive investigation
- **Professional documentation** following industry incident response standards

---

## 📋 Table of Contents

- [🎯 Executive Summary](#-executive-summary)
- [🚨 Incident Overview](#-incident-overview)
- [🏗️ Technical Environment](#️-technical-environment)
- [🔍 Attack Analysis](#-attack-analysis)
- [🛡️ Incident Response Process](#️-incident-response-process)
- [🖼️ Evidence Gallery](#️-evidence-gallery)
- [📄 Professional Documentation](#-professional-documentation)
- [🎯 Skills Demonstrated](#-skills-demonstrated)
- [📈 Lessons Learned](#-lessons-learned)
- [🔧 Technical Appendix](#-technical-appendix)

---

## 🚨 Incident Overview

### Timeline and Classification
| Field | Details |
|-------|---------|
| **Incident ID** | INC-2025-0622-001 |
| **Classification** | Critical Domain Compromise |
| **Date Range** | June 21-22, 2025 |
| **Duration** | 24-hour sustained attack window |
| **Discovery Method** | SIEM log analysis during routine security review |
| **Severity Level** | CRITICAL |

### Attack Vector and Methods
**Primary Attack Vector**: AWS Security Group misconfiguration exposing Active Directory services to the internet (0.0.0.0/0)

**Exposed Services**:
- Port 88 (Kerberos)
- Port 389 (LDAP)  
- Port 445 (SMB)
- All ports (complete exposure)

**Attack Methodology**:
1. **Network Reconnaissance**: ANONYMOUS LOGON exploitation for domain enumeration
2. **Automated Brute Force**: 36,822 failed authentication attempts with 2-second intervals
3. **Privilege Escalation**: krbtgt account creation and Domain Admin group modification
4. **Persistent Access**: Golden Ticket attack capability establishment

### Business Impact Assessment
- **Severity**: CRITICAL
- **Domain Control**: Complete administrative access achieved
- **Data Exposure Risk**: Full domain data access capability
- **Recovery Complexity**: Domain rebuild recommended due to krbtgt compromise
- **Compliance Impact**: Potential regulatory notification requirements

---

## 🏗️ Technical Environment

### Infrastructure Architecture

**Cloud Infrastructure**:
```
┌─────────────────────────────────────────────────────────────┐
│                     AWS ap-south-1                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   ADDC01    │  │  Target-PC   │  │  Splunk Enterprise  │ │
│  │ Domain      │  │  Member      │  │  SIEM Platform      │ │
│  │ Controller  │  │  Server      │  │  172.31.x.x         │ │
│  │ (Victim)    │  │ (Victim)     │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
│                                                             │
│  ┌─────────────┐  ┌─────────────────────────┐               │
│  │ Kali Linux  │  │ Analysis Workstation    │               │
│  │ Red Team    │  │ Python Automation Server│               │
│  │ Platform    │  │ 172.31.x.x              │               │
│  └─────────────┘  └─────────────────────────┘               │
└─────────────────────────────────────────────────────────────┘
```

### Technologies and Tools Used
- **Operating Systems**: Windows Server 2025, Kali Linux 2024
- **Directory Services**: Active Directory Domain Services
- **SIEM Platform**: Splunk Enterprise with Universal Forwarders
- **Cloud Provider**: Amazon Web Services (EC2, Security Groups)
- **Monitoring**: Windows Event Logs, Splunk SIEM
- **Forensics**: EBS snapshots, SIEM log preservation

### Critical Security Misconfiguration

**Vulnerable Configuration (Root Cause)**:
```json
{
  "SecurityGroup": "sg-vulnerable",
  "Rules": {
    "Type": "All traffic",
    "Protocol": "All", 
    "Port": "All",
    "Source": "0.0.0.0/0",
    "Description": "CRITICAL MISCONFIGURATION - Internet exposed AD services"
  }
}
```

**Remediated Configuration**:
```json
{
  "SecurityGroup": "sg-hardened", 
  "Rules": {
    "Type": "Custom TCP",
    "Protocol": "TCP",
    "Port": "88,389,445",
    "Source": "172.31.0.0/16",
    "Description": "VPC-only access for AD services"
  }
}
```

---

## 🔍 Attack Analysis

### Pre-Containment Evidence
The attack was initially discovered through AWS Security Group analysis and Windows Event Log examination.

![Security Groups Pre-Containment](01_Pre_Containment_Evidence/Security%20Group%20Pre-Containment%201.png)
*AWS Security Group configuration showing complete internet exposure (0.0.0.0/0)*

![Failed Login Events](01_Pre_Containment_Evidence/Real%20Attack%20Same%20IP%204625%20Events.png)
*Windows Event ID 4625 showing massive failed login attempts from external IP*

![Successful Login Details](01_Pre_Containment_Evidence/Real%20Attack%20Same%20IP%204624%20Event%20Sample%20Details.png)
*Successful ANONYMOUS LOGON event details revealing compromise methodology*

### Detailed Forensic Analysis

#### Phase 1: Initial Reconnaissance
**ANONYMOUS LOGON Exploitation**:
- NULL session authentication to Windows services
- Legacy SMB/CIFS vulnerability exploitation  
- Unauthenticated domain enumeration capability

**Splunk Query for Detection**:
```splunk
index="endpoint" EventCode=4625 | stats count by Source_Network_Address | sort -count
```

#### Phase 2: Attack Timeline Reconstruction

![Attack Timeline](02_Attack_Analysis/ANONYMOUS%20LOGON%20Attack%20Timeline:%20Sustained%20Unauthorized%20Access%20Pattern.png)
*Complete attack timeline showing sustained unauthorized access pattern*

![Critical Privilege Escalation](02_Attack_Analysis/CRITICAL:%20Anonymous%20Attacker%20Domain%20Privilege%20Escalation%20Sequence.png)
*Critical evidence of privilege escalation to Domain Admin by external threat actor*

![Domain Takeover Timeline](02_Attack_Analysis/Domain%20Takeover%20Timeline:%20Complete%20Attack%20Progression.png)
*Complete domain takeover progression from initial access to administrative control*

**Attack Pattern Analysis**:
```splunk
index="endpoint" EventCode=4625 Source_Network_Address="186.10.23.226"
| timechart span=1m count
```

**Key Findings**:
- 22-minute sustained attack window
- Consistent 2-second intervals indicating automated tooling
- 109 successful ANONYMOUS LOGON sessions (Event ID 4624, Logon Type 3)

#### Phase 3: Privilege Escalation (Critical)

![Compromise Assessment](02_Attack_Analysis/Compromise%20Assessment:%20External%20IP%20Successful%20Authentication%20by%20Account.png)
*Assessment showing successful external authentication by compromised accounts*

![Damage Assessment](02_Attack_Analysis/Damage%20Assessment%20from%20krbtgt%20Account.png)
*Critical: Damage assessment revealing krbtgt account compromise*

**Persistence Hunting Query**:
```splunk
index="endpoint" (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| search Account_Name="ANONYMOUS LOGON"
```

**Critical Compromise Indicators**:
- **Event 4720**: krbtgt user account created by ANONYMOUS LOGON
- **Event 4732**: Accounts added to Domain Admins group
- **Event 4728**: Security group memberships modified

![Persistence Hunt Evidence](02_Attack_Analysis/Persistence%20Hunt%20(Account%20Changes,%20New%20Accounts,%20or%20Privilege%20Escalations).png)
*Comprehensive persistence hunting showing account changes and privilege escalations*

### Kerberos Infrastructure Compromise

**Why krbtgt Compromise is Critical**:
- Kerberos Ticket Granting Ticket service account
- Most privileged account in Active Directory
- Enables "Golden Ticket" attacks for unlimited persistence
- Allows privilege escalation to any domain resource

**Attack Capabilities Gained**:
- Unlimited domain administrative access
- Ability to create/modify/delete any domain object
- Persistent access independent of password changes
- Potential for lateral movement to all domain-joined systems

---

## 🛡️ Incident Response Process

### Detection and Investigation

![External Threat Landscape](02_Attack_Analysis/External%20Threat%20Landscape.png)
*Analysis of external threat landscape and attack origins*

![Legitimate vs Malicious Traffic](02_Attack_Analysis/Legitimate%20vs%20Malicious%20Traffic%20Analysis.png)
*Traffic analysis distinguishing legitimate operations from malicious activity*

**Initial Discovery Process**:
1. **Routine SIEM Review**: Analyzing logs during penetration testing preparation
2. **Anomaly Identification**: Unusual authentication patterns from external IP
3. **Threat Validation**: Confirming malicious activity vs. legitimate testing
4. **Scope Assessment**: Determining full extent of compromise

### Immediate Containment Actions

![Network Isolation](03_Containment_Actions/Immediate%20Containment:%20Removed%20Internet%20Access%20to%20All%20Services.png)
*Immediate containment: Removed internet access to all services*

![Explicit IP Block](03_Containment_Actions/Explicit%20Block%20for%20the%20Attacker%20on%20Network%20ACL.png)
*Explicit block implemented for attacker IP on Network ACL*

**Immediate Response (Within 2 hours of discovery)**:
1. **Network Isolation**: Modified AWS Security Groups to VPC-only access
2. **Attack Termination**: Confirmed cessation of malicious authentication attempts
3. **Evidence Preservation**: Created EBS snapshots before any remediation
4. **Stakeholder Notification**: Documented incident for organizational awareness

### Forensic Investigation

![No File Sharing Discovered](02_Attack_Analysis/No%20File%20Sharing%20Discovered.png)
*Investigation results showing no file sharing or data exfiltration activity*

![Damage Assessment No Results](Damage%20Assessment%20(No%20Results).png)
*Comprehensive damage assessment confirming no additional compromise beyond documented activities*

**Evidence Collection**:
- Complete SIEM log preservation (2+ weeks of data)
- EBS snapshots of all affected systems
- Network flow logs and security group configurations
- Professional incident documentation

---

## 📄 Professional Documentation

### Executive Incident Report
**[Complete Incident Report](incident_report.md)**
- **Classification**: Critical Domain Compromise  
- **Business Impact**: Complete domain administrative access by external threat actor
- **Root Cause**: AWS Security Group misconfiguration exposing AD services
- **Recommendations**: Domain rebuild and architecture hardening

### Technical Analysis Blog
**[Detailed Technical Analysis](technical_blog.md)**
- **SIEM Investigation**: Complete Splunk-based forensic workflow
- **Attack Vector Analysis**: ANONYMOUS LOGON exploitation methodology
- **Timeline Reconstruction**: Minute-by-minute attack progression
- **Lessons Learned**: Security architecture and response improvements

### Professional Portfolio Content
**[LinkedIn Professional Showcase](linkedin_post.md)**
- **Skills Demonstration**: Advanced threat hunting and digital forensics
- **Real-World Experience**: Professional incident response under pressure
- **Community Contribution**: Threat intelligence sharing and security awareness

---

## 🎯 Skills Demonstrated

### Advanced Technical Competencies

**Digital Forensics & Incident Response**:
- Complete incident timeline reconstruction using SIEM data
- Forensic evidence preservation and chain of custody
- Root cause analysis of complex security misconfigurations
- Professional incident documentation following NIST standards

**Advanced Threat Hunting**:
- SIEM-driven threat detection and behavioral analysis
- Automated attack pattern recognition and correlation
- Privilege escalation detection and investigation
- Advanced persistent threat identification

**Active Directory Security**:
- Kerberos attack analysis and Golden Ticket implications
- ANONYMOUS LOGON vulnerability assessment
- Domain compromise impact analysis
- Windows Event Log forensic correlation

**Cloud Security Architecture**:
- AWS Security Group configuration and hardening
- Network segmentation and zero-trust implementation
- Infrastructure security assessment and remediation
- Multi-cloud security monitoring integration

### Professional Capabilities

**Executive Communication**:
- Technical findings translated to business impact
- Professional incident reporting under time pressure
- Stakeholder communication during active incidents
- Risk assessment and strategic remediation planning

**Project Management**:
- Complete incident response lifecycle coordination
- Multi-system environment management
- Evidence preservation workflow development
- Cross-functional team coordination under pressure

---

## 📈 Lessons Learned

### What Worked Well
- **Rapid Detection**: SIEM-enabled discovery of ongoing attack within hours
- **Effective Containment**: Immediate network isolation stopped further compromise
- **Comprehensive Documentation**: Professional incident response following industry standards
- **Complete Forensic Analysis**: Full timeline reconstruction with business impact assessment

### Critical Improvements Identified
- **Preventive Controls**: Network segmentation prevents initial access
- **Real-time Alerting**: Automated monitoring of privileged account modifications
- **Configuration Management**: Security group changes require approval workflows
- **Incident Response Automation**: Automated containment for known attack patterns

### Security Architecture Enhancements
1. **Zero-Trust Implementation**: Default-deny network access policies
2. **Privileged Access Management**: PAM solution for administrative access
3. **Advanced Threat Detection**: Behavioral analytics and UEBA deployment
4. **Continuous Monitoring**: Real-time security posture assessment

---

## 🔧 Technical Appendix

### Key SIEM Queries Developed

```splunk
# Initial threat detection
index="endpoint" EventCode=4625 | stats count by Source_Network_Address | sort -count

# Attack timeline analysis  
index="endpoint" EventCode=4625 Source_Network_Address="186.10.23.226" 
| timechart span=1m count

# Privilege escalation hunting
index="endpoint" (EventCode=4720 OR EventCode=4728 OR EventCode=4732) 
| search Account_Name="ANONYMOUS LOGON"

# Successful authentication analysis
index="endpoint" EventCode=4624 Source_Network_Address="186.10.23.226" 
| table _time, Account_Name, Logon_Type, Computer_Name
| sort _time

# Complete attack reconstruction
index="endpoint" Account_Name="ANONYMOUS LOGON" 
| eval Activity_Type=case(
    EventCode=4624, "Network Access",
    EventCode=4720, "User Creation", 
    EventCode=4728, "Group Addition",
    EventCode=4732, "Group Modification",
    1=1, "Other"
)
| table _time, Activity_Type, Target_Account_Name
| sort _time
```

### Windows Event IDs Reference
- **4624**: Successful Logon
- **4625**: Failed Logon  
- **4720**: User Account Created
- **4728**: Member Added to Security-Enabled Global Group
- **4732**: Member Added to Security-Enabled Local Group

### Attack Timeline Summary
```
June 21, 15:34:56 - Initial privilege escalation activities detected
June 21, 20:32:24 - First sustained access session begins  
June 22, 02:19:15 - Peak activity period begins (54 seconds)
June 22, 02:20:09 - Peak activity concludes (50+ authentication events)
June 22, 10:26:00 - Final access session begins
June 22, 10:26:44 - Attack concludes (network isolation implemented)
```

---

## 🤝 Repository Information

### Purpose and Scope
This repository demonstrates professional-level cybersecurity incident response capabilities through documentation of a real security incident. The investigation, containment, and forensic analysis showcase advanced technical skills and professional methodology essential for senior cybersecurity roles.

### Educational Value
- **Real-World Experience**: Genuine incident response under operational pressure
- **Technical Methodology**: Advanced SIEM-based investigation techniques
- **Professional Documentation**: Industry-standard incident reporting
- **Lessons Learned**: Security architecture and response improvements

### Security Considerations
- All sensitive information sanitized with appropriate placeholder values
- No actual credentials or production system details exposed
- Lab environment isolation ensures operational security
- Professional information handling throughout documentation

---

## 📞 Contact & Career Development

**Professional Cybersecurity Portfolio**  
**Advanced Incident Response Capabilities**

This repository demonstrates senior-level cybersecurity incident response expertise developed through hands-on experience with real security events. The complete investigation, documentation, and remediation process showcases technical proficiency and professional methodology required for advanced cybersecurity positions.

### Career Impact Highlights
- **Real-World IR Experience**: Managing actual security incidents with business impact
- **Advanced Technical Skills**: Multi-domain cybersecurity expertise integration
- **Professional Communication**: Executive-level incident reporting capabilities
- **Continuous Learning**: Proactive skill development through practical application

---

**Tags**: `incident-response` `cybersecurity` `threat-hunting` `digital-forensics` `active-directory` `siem` `splunk` `aws-security` `kerberos` `security-analysis` `professional-portfolio` `career-development`

*This incident response documentation represents professional cybersecurity capabilities developed through real-world experience. All technical details preserved for educational value while maintaining appropriate information security practices.*
