# 📜 NSE Scripts Usage Guide

## 🔍 What are NSE Scripts?

NSE (Nmap Scripting Engine) is one of Nmap's most powerful features. You can enhance your network scans with more detailed and comprehensive results using scripts written in the Lua programming language.

## 🎯 Advantages of NSE Scripts

- **Detailed Service Detection**: Not just open/closed ports, but detailed service information
- **Vulnerability Detection**: Automatically detects known security vulnerabilities
- **Banner Grabbing**: Collects service banner information
- **SSL/TLS Analysis**: Checks certificate information and security settings
- **HTTP Service Analysis**: Performs detailed analysis of web services
- **Custom Functionality**: Extends Nmap's capabilities with custom scripts

## 🚀 Basic Usage

### 1. **Default Scripts**
If you don't specify any scripts, the application automatically uses these scripts:
```
banner,http-title,ssl-cert,ssh-hostkey
```

### 2. **Single Script Usage**
```
banner
```

### 3. **Multiple Scripts**
You can use multiple scripts by separating them with commas:
```
banner,http-title,ssl-cert
```

### 4. **Script Categories**
You can run all scripts in a category by using the category name:
```
vuln
safe
auth
```

## 📋 Popular NSE Scripts

### **🔐 Security Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `vuln` | Vulnerability scanning | `vuln` |
| `exploit` | Exploit detection | `exploit` |
| `malware` | Malware detection | `malware` |
| `intrusive` | Aggressive security tests | `intrusive` |
| `dos` | Denial of Service tests | `dos` |
| `brute` | Brute force attacks | `brute` |

### **🌐 HTTP/Web Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `http-title` | Web page title | `http-title` |
| `http-headers` | HTTP headers | `http-headers` |
| `http-methods` | Supported HTTP methods | `http-methods` |
| `http-enum` | Web directory and file scanning | `http-enum` |
| `http-sql-injection` | SQL injection test | `http-sql-injection` |
| `http-xssed` | Cross-site scripting test | `http-xssed` |
| `http-wordpress-enum` | WordPress enumeration | `http-wordpress-enum` |
| `http-apache-server-status` | Apache server status | `http-apache-server-status` |

### **🔒 SSL/TLS Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `ssl-cert` | SSL certificate information | `ssl-cert` |
| `ssl-enum-ciphers` | Supported encryption algorithms | `ssl-enum-ciphers` |
| `ssl-heartbleed` | Heartbleed vulnerability test | `ssl-heartbleed` |
| `ssl-poodle` | POODLE vulnerability test | `ssl-poodle` |
| `ssl-dh-params` | Diffie-Hellman parameters | `ssl-dh-params` |
| `ssl-ccs-injection` | CCS injection test | `ssl-ccs-injection` |

### **🔑 Authentication Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `ssh-hostkey` | SSH key information | `ssh-hostkey` |
| `ssh-auth-methods` | SSH authentication methods | `ssh-auth-methods` |
| `ssh-brute` | SSH brute force | `ssh-brute` |
| `ftp-anon` | Anonymous FTP access | `ftp-anon` |
| `ftp-brute` | FTP brute force | `ftp-brute` |
| `smb-enum-shares` | SMB shares | `smb-enum-shares` |
| `smb-brute` | SMB brute force | `smb-brute` |

### **📊 Information Gathering Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `banner` | Service banner information | `banner` |
| `version` | Service version information | `version` |
| `dns-zone-transfer` | DNS zone transfer test | `dns-zone-transfer` |
| `snmp-info` | SNMP information | `snmp-info` |
| `snmp-brute` | SNMP brute force | `snmp-brute` |
| `ldap-rootdse` | LDAP root DSE | `ldap-rootdse` |

### **🗄️ Database Scripts**
| Script | Description | Usage |
|--------|-------------|-------|
| `mysql-info` | MySQL information | `mysql-info` |
| `mysql-brute` | MySQL brute force | `mysql-brute` |
| `postgresql-brute` | PostgreSQL brute force | `postgresql-brute` |
| `mssql-info` | MSSQL information | `mssql-info` |
| `oracle-brute` | Oracle brute force | `oracle-brute` |

## 🎯 Usage Scenarios

### **1. Web Service Scanning**
```
http-title,http-headers,http-methods,ssl-cert
```

### **2. Vulnerability Scanning**
```
vuln,exploit,ssl-heartbleed,ssl-poodle
```

### **3. SSH Service Analysis**
```
ssh-hostkey,ssh-auth-methods,banner
```

### **4. Comprehensive Scanning**
```
banner,http-title,ssl-cert,ssh-hostkey,vuln
```

### **5. Quick Information Gathering**
```
banner,version,http-title
```

### **6. Database Security Testing**
```
mysql-info,mysql-brute,postgresql-brute,mssql-info
```

### **7. Network Service Discovery**
```
smb-enum-shares,ftp-anon,telnet-encryption,snmp-info
```

## ⚠️ Important Notes

### **Security Warnings**
- `vuln` and `exploit` scripts can be aggressive
- May leave log entries on target systems
- Only use on your own systems or with explicit permission
- Some scripts may trigger intrusion detection systems

### **Performance Considerations**
- Using too many scripts can slow down scans significantly
- `intrusive` scripts are particularly slow
- Adjust timeout settings based on target system response times
- Consider network bandwidth limitations

### **Error Handling**
- Some scripts may not work with certain services
- Script errors usually don't stop the entire scan
- Error messages can be found in log files
- Test scripts on your own systems first

## 🔧 Advanced Usage

### **Script Arguments**
Some scripts accept parameters:
```
http-enum --script-args http-enum.basepath=/
mysql-brute --script-args mysql-brute.passdb=passwords.txt
```

### **Script Categories**
- `safe`: Safe scripts (default)
- `intrusive`: Aggressive scripts
- `vuln`: Vulnerability scripts
- `exploit`: Exploit scripts
- `malware`: Malware detection scripts
- `discovery`: Discovery scripts
- `auth`: Authentication scripts
- `brute`: Brute force scripts
- `dos`: Denial of Service scripts

### **Custom Script Combinations**
```
# Web security scanning
http-title,http-headers,http-sql-injection,ssl-cert,ssl-enum-ciphers

# SSH security scanning
ssh-hostkey,ssh-auth-methods,ssh-brute

# Database scanning
mysql-info,postgresql-brute,mssql-info,oracle-brute

# Network services scanning
smb-enum-shares,ftp-anon,telnet-encryption,snmp-info
```

### **Timing and Performance**
```
# Fast scan with basic scripts
banner,http-title,ssl-cert

# Comprehensive scan (slower)
vuln,exploit,malware,ssl-cert,http-enum

# Stealth scan
safe,banner,version
```

## 📝 Practical Examples

### **1. Basic Web Scan**
```
http-title,http-headers,ssl-cert
```

### **2. Security-Focused Scan**
```
vuln,ssl-heartbleed,ssl-poodle,http-sql-injection
```

### **3. Service Discovery**
```
banner,version,http-title,ssh-hostkey
```

### **4. Comprehensive Security Scan**
```
vuln,exploit,malware,ssl-cert,http-enum
```

### **5. Database Security Assessment**
```
mysql-info,mysql-brute,postgresql-brute,mssql-info
```

### **6. Network Infrastructure Scan**
```
smb-enum-shares,ftp-anon,snmp-info,ldap-rootdse
```

## 🎯 Best Practices

### **1. Start Simple**
Begin with basic scripts like `banner,http-title,ssl-cert`

### **2. Security First**
Use `vuln` scripts carefully and only on authorized systems

### **3. Performance Matters**
Don't use too many scripts at once

### **4. Target-Specific**
Choose scripts based on the target system type

### **5. Test First**
Always test on your own systems before scanning others

### **6. Documentation**
Keep records of what scripts you used and their results

### **7. Legal Compliance**
Ensure you have proper authorization before scanning

## 🔍 Troubleshooting

### **Common Issues**
- **Scripts not running**: Check if the service is actually running
- **Timeout errors**: Increase timeout values for slow networks
- **Permission denied**: Ensure you have proper access rights
- **No results**: Some scripts only work with specific service versions

### **Debug Tips**
- Use `-v` flag for verbose output
- Check Nmap logs for detailed error messages
- Test individual scripts before combining them
- Verify target system is reachable

## 📚 Additional Resources

- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [NSE Script Database](https://nmap.org/nsedoc/)
- [NSE Script Examples](https://nmap.org/nsedoc/scripts/)
- [Lua Programming Guide](https://www.lua.org/manual/5.1/)
- [Nmap Scripting Engine Tutorial](https://nmap.org/book/nse-tutorial.html)

## 🚀 Quick Reference

### **Most Used Scripts**
```
banner,http-title,ssl-cert,ssh-hostkey,vuln
```

### **Web Security**
```
http-title,http-headers,http-sql-injection,ssl-cert,ssl-enum-ciphers
```

### **Network Discovery**
```
banner,version,smb-enum-shares,ftp-anon,snmp-info
```

### **Database Security**
```
mysql-info,mysql-brute,postgresql-brute,mssql-info
```

---

**⚠️ Legal Notice**: Only use these scripts on systems you own or have explicit permission to test. Unauthorized scanning may violate laws and regulations. Always ensure compliance with local laws and organizational policies.
