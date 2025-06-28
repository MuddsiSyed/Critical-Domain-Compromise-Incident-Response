# Case Study: Active Directory Domain Compromise via ANONYMOUS LOGON Exploitation

*A detailed technical analysis of a real security incident from detection through forensic investigation*

## Introduction

During the development of my cybersecurity lab environment, I encountered an unexpected learning opportunity: a real external attack against my Active Directory infrastructure. This post details the complete incident response process, from initial detection through forensic analysis and containment.

## Lab Environment Architecture

**Infrastructure Components:**
- AWS EC2 instances in ap-south-1 region
- Windows Server 2025 Domain Controller (ADDC01)
- Windows Server 2025 Member Server (Target-PC)
- Splunk Enterprise SIEM with Universal Forwarders
- Kali Linux penetration testing platform

**Critical Misconfiguration:**
AWS Security Groups inadvertently exposed AD services to the internet (0.0.0.0/0):
- Port 88 (Kerberos)
- Port 389 (LDAP)
- Port 445 (SMB)

## Timeline of Discovery

### Initial Detection
While reviewing Splunk logs for legitimate penetration testing preparation, I discovered an anomalous pattern:

```splunk
index="endpoint" EventCode=4625 | stats count by Source_Network_Address | sort -count
```

**Results showed 36,822 failed login attempts from 186.10.23.226 - clearly not my testing activity.**

### Attack Analysis

**Failed Authentication Pattern:**
```splunk
index="endpoint" EventCode=4625 Source_Network_Address="186.10.23.226"
| timechart span=1m count
```
This revealed a 22-minute sustained attack window with consistent 2-second intervals, indicating automated tooling.

**Successful Authentication Discovery:**
```splunk
index="endpoint" EventCode=4624 Source_Network_Address="186.10.23.226"
| table _time, Account_Name, Logon_Type, Computer_Name
```
**Critical Finding: 109 successful ANONYMOUS LOGON sessions (Logon Type 3 - Network)**

## Technical Analysis of ANONYMOUS LOGON Exploitation

### What is ANONYMOUS LOGON?
In Windows environments, ANONYMOUS LOGON represents:
- NULL session authentication to Windows services
- Legacy SMB/CIFS vulnerability allowing unauthenticated access
- Network-level enumeration capability without valid credentials

### Attack Progression Analysis

**Phase 1: Network Reconnaissance**
The attacker leveraged ANONYMOUS LOGON to:
- Enumerate domain structure
- Map network topology  
- Identify privileged accounts
- Discover service configurations

**Phase 2: Privilege Escalation**
Most concerning discovery via persistence hunting:
```splunk
index="endpoint" (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| search Account_Name="ANONYMOUS LOGON"
```

**Results showed ANONYMOUS LOGON performed:**
- Event 4720: Created krbtgt user account
- Event 4732: Added accounts to Domain Admins group
- Event 4728: Modified security group memberships

### Kerberos Infrastructure Compromise

The creation of a krbtgt account represents complete domain compromise:

**Why krbtgt Matters:**
- Kerberos Ticket Granting Ticket service account
- Most privileged account in Active Directory
- Enables "Golden Ticket" attacks for persistent access
- Allows unlimited privilege escalation

## Forensic Timeline Reconstruction

### Attack Sequence Analysis
```splunk
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

**Complete Attack Chain:**
1. **June 21, 15:34:56**: Initial privilege escalation activities
2. **June 21, 20:32:24**: First sustained access session
3. **June 22, 02:19:15-02:20:09**: Peak activity (54 seconds, 50+ logins)
4. **June 22, 10:26:00-10:26:44**: Final access session

## Impact Assessment

### Confirmed Compromises
- **Complete domain administrative access**
- **Kerberos ticket granting infrastructure control**
- **Advanced persistent threat establishment**
- **Potential for lateral movement to all domain systems**

### Business Risk Analysis
- **Data exfiltration capability**: Full domain data access
- **Operational disruption potential**: Complete system control
- **Compliance implications**: Depending on data classification
- **Recovery complexity**: Potential full domain rebuild required

## Incident Response Actions

### Immediate Containment
1. **Network Isolation**: Modified AWS Security Groups to VPC-only access
2. **Attack Termination**: Confirmed no further successful logins
3. **Evidence Preservation**: EBS snapshots captured before changes

### Forensic Documentation
- Complete SIEM log preservation
- Timeline reconstruction with business impact
- Attack vector analysis and root cause identification
- Professional incident reporting for organizational learning

### Threat Intelligence Contribution
- Added 186.10.23.226 to local threat database
- Community reporting to AbuseIPDB and threat intelligence platforms
- Documentation of attack techniques for collective defense

## Lessons Learned

### Security Architecture
- **Network segmentation is critical**: AD services should never be internet-accessible
- **Least privilege principles**: Default-deny security group policies
- **Monitoring coverage**: Real-time alerting on privileged account changes

### Incident Response
- **SIEM value demonstration**: Splunk enabled complete attack reconstruction
- **Automation opportunities**: Security group changes should trigger alerts
- **Documentation importance**: Professional incident reports enable learning

### Technical Skills Development
- **Real-world experience invaluable**: Simulated incidents cannot replicate actual pressure
- **Cross-domain knowledge required**: Cloud security + AD security + forensics
- **Communication skills critical**: Technical findings must translate to business impact

## Remediation Strategy

### Immediate Actions
- Security group hardening (completed)
- Network access review and restriction
- Privileged account audit and cleanup

### Long-term Recommendations
- **Complete domain rebuild**: Due to krbtgt compromise
- **Zero-trust architecture implementation**
- **Advanced threat detection deployment**
- **Incident response automation development**

## Conclusion

This incident transformed from a learning exercise into a comprehensive real-world incident response scenario. The experience demonstrated the critical importance of:

- Proper security configuration management
- Real-time monitoring and alerting
- Professional incident response procedures
- Continuous threat intelligence integration

Most importantly, it reinforced that cybersecurity expertise comes from hands-on experience with real security events, not just theoretical knowledge.

The complete forensic analysis, timeline reconstruction, and professional documentation from this incident will serve as valuable reference material for future security operations and career development.

---

*Technical details have been preserved for educational value while ensuring no sensitive information is disclosed. This incident occurred in a controlled lab environment designed for cybersecurity skill development.*

## Technical Appendix

### Key Splunk Queries Used
```splunk
# Initial threat detection
index="endpoint" EventCode=4625 | stats count by Source_Network_Address | sort -count

# Attack timeline analysis  
index="endpoint" EventCode=4625 Source_Network_Address="186.10.23.226" | timechart span=1m count

# Privilege escalation hunting
index="endpoint" (EventCode=4720 OR EventCode=4728 OR EventCode=4732) | search Account_Name="ANONYMOUS LOGON"

# Successful authentication analysis
index="endpoint" EventCode=4624 Source_Network_Address="186.10.23.226" | table _time, Account_Name, Logon_Type
```

### Windows Event IDs Referenced
- **4624**: Successful Logon
- **4625**: Failed Logon  
- **4720**: User Account Created
- **4728**: Member Added to Security-Enabled Global Group
- **4732**: Member Added to Security-Enabled Local Group

### AWS Security Configuration
```json
// Insecure (original)
{
  "Type": "All traffic",
  "Protocol": "All", 
  "Port": "All",
  "Source": "0.0.0.0/0"
}

// Secure (remediated)
{
  "Type": "Custom TCP",
  "Protocol": "TCP",
  "Port": "88,389,445", 
  "Source": "172.31.0.0/16"
}
```