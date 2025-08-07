# 🔐 Técnicas Completas de Pentesting en Active Directory

---

## 📋 Índice General

Este documento recopila todas las técnicas de pentesting en Active Directory organizadas por categorías para facilitar la documentación y selección de técnicas a implementar.

### 📂 Categorías de Técnicas

1. [Reconocimiento y Enumeración](#1-reconocimiento-y-enumeración)
2. [Ataques de Credenciales](#2-ataques-de-credenciales)
3. [Ataques Kerberos](#3-ataques-kerberos)
4. [Ataques de Relay](#4-ataques-de-relay)
5. [Escalada de Privilegios](#5-escalada-de-privilegios)
6. [Persistencia](#6-persistencia)
7. [Movimiento Lateral](#7-movimiento-lateral)
8. [Ataques de Certificados (ADCS)](#8-ataques-de-certificados-adcs)
9. [Ataques de Delegación](#9-ataques-de-delegación)
10. [Ataques Post-Explotación](#10-ataques-post-explotación)

---

## 1. Reconocimiento y Enumeración

### 1.1 Enumeración de Dominio

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Enumeración SMB** | enum4linux, smbclient, smbmap, crackmapexec | ✅ (Enum-SMB.md) |
| **Enumeración LDAP** | ldapsearch, ldapdomaindump, windapsearch | ✅ (BruteForce-Ldap.md) |
| **Enumeración RPC** | rpcclient, rpcinfo | ✅ (Enum-Rpcclient.md) |
| **Enumeración DNS** | dnsrecon, dnsenum, dig | ✅ (Enum-DNS.md) |
| **Enumeración NTP** | ntpq, ntpdate | ✅ (Enum-NTP.md) |
| **Anonymous Logon** | rpcclient, smbclient | ✅ (Anonymous-Logon-Guest.md) |

### 1.2 Enumeración de Usuarios

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **User Enumeration via SMB** | enum4linux, crackmapexec | ✅ (EnumUsers.md) |
| **User Enumeration via LDAP** | ldapsearch, windapsearch | ✅ (EnumUsers.md) |
| **User Enumeration via Kerberos** | kerbrute, nmap | ✅ (BruteForce-Kerberos.md) |
| **ASREPRoast User Discovery** | GetNPUsers.py, Rubeus | ✅ (As-Rep-Roasting.md) |
| **SPN User Discovery** | GetUserSPNs.py, Rubeus | ✅ (Kerberoasting.md) |

### 1.3 Herramientas de Enumeración Automatizada

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **BloodHound** | SharpHound, BloodHound-py | ✅ (BloodHound-py.md) |
| **ADRecon** | ADRecon.ps1 | ❌ |
| **PingCastle** | PingCastle | ❌ |
| **PlumHound** | PlumHound | ✅ (PlumHound.md) |
| **NetExec (ex-CrackMapExec)** | netexec, crackmapexec | ✅ (Lateral-nxc.md) |

---

## 2. Ataques de Credenciales

### 2.1 Ataques de Fuerza Bruta

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Kerberos Brute Force** | kerbrute, Rubeus | ✅ (BruteForce-Kerberos.md) |
| **LDAP Brute Force** | patator, hydra, crackmapexec | ✅ (BruteForce-Ldap.md) |
| **SMB Brute Force** | crackmapexec, hydra, medusa | ❌ |
| **RDP Brute Force** | crowbar, hydra, ncrack | ❌ |
| **WinRM Brute Force** | crackmapexec, evil-winrm | ❌ |

### 2.2 Ataques de Diccionario y Spray

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Password Spraying** | crackmapexec, DomainPasswordSpray | ✅ (Password-Spraying.md) |
| **Credential Stuffing** | crackmapexec, Spray-Passwords | ❌ |
| **Smart Brute Force** | kerbrute con listas inteligentes | ❌ |

### 2.3 Extracción de Credenciales

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **LSASS Dump** | mimikatz, procdump, comsvcs.dll | ❌ |
| **SAM/SYSTEM Dump** | secretsdump.py, mimikatz | ❌ |
| **NTDS.dit Extraction** | secretsdump.py, impacket | ✅ (NTDS-dit-Extraction.md) |
| **DCSync** | mimikatz, secretsdump.py | ✅ (DCSync.md) |
| **Group Policy Passwords** | Get-GPPPassword, gpp-decrypt | ❌ |

---

## 3. Ataques Kerberos

### 3.1 Ataques de Roasting

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Kerberoasting** | GetUserSPNs.py, Rubeus | ✅ (Kerberoasting.md) |
| **AS-REP Roasting** | GetNPUsers.py, Rubeus | ✅ (As-Rep-Roasting.md) |
| **TGT-REQ Roasting** | Rubeus, KrbRelayUp | ❌ |
| **Targeted Kerberoasting** | GetUserSPNs.py con targets específicos | ❌ |

### 3.2 Ataques de Tickets

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Golden Ticket** | mimikatz, ticketer.py | ✅ (Golden-Ticket.md) |
| **Silver Ticket** | mimikatz, ticketer.py | ✅ (Silver-Ticket.md) |
| **Diamond Ticket** | Rubeus, mimikatz | ❌ |
| **Sapphire Ticket** | Rubeus | ❌ |
| **Pass-the-Ticket** | mimikatz, getTGT.py | ✅ (PassTheHash.md, Impersonation-Attacks.md) |
| **Overpass-the-Hash** | mimikatz, getTGT.py | ✅ (Impersonation-Attacks.md) |

### 3.3 Ataques de Delegación Kerberos

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Unconstrained Delegation** | Rubeus, findDelegation.py | ✅ (Unconstrained-Delegation.md) |
| **Constrained Delegation** | Rubeus, getST.py | ✅ (Constrained-Delegation.md) |
| **Resource-Based Constrained Delegation** | Rubeus, rbcd.py | ✅ (RBCD.md) |
| **S4U2Self/S4U2Proxy Abuse** | Rubeus, getST.py | ✅ (S4U2Self-S4U2Proxy-Abuse.md) |

---

## 4. Ataques de Relay

### 4.1 NTLM Relay

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **SMB Relay** | ntlmrelayx.py, Responder | ✅ (SmbRelay-Attack.md, Responder-Ntlmrelay.md) |
| **HTTP Relay** | ntlmrelayx.py | ✅ (RelayAttack-attacks.md, RelayAttacks-Teoric-Defense.md) |
| **LDAP Relay** | ntlmrelayx.py --target ldap | ✅ (RelayAttack-attacks.md, RelayAttacks-Teoric-Defense.md) |
| **MSSQL Relay** | ntlmrelayx.py --target mssql | ❌ |
| **Cross-Protocol Relay** | ntlmrelayx.py multiples targets | ✅ (RelayAttack-attacks.md) |

### 4.2 Coerción de Autenticación

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **PrinterBug/SpoolSample** | printerbug.py, SpoolSample | ✅ (Coerce.md, RelayAttack-attacks.md) |
| **PetitPotam** | PetitPotam.py | ✅ (Coerce.md, RelayAttack-attacks.md) |
| **PrivExchange** | privexchange.py | ❌ |
| **CoercedPotato** | CoercedPotato | ❌ |
| **DFSCoerce** | dfscoerce.py | ✅ (Coerce.md, RelayAttack-attacks.md) |

### 4.3 Relay con ADCS

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **ADCS HTTP Relay** | ntlmrelayx.py --target http://ca/certsrv | ❌ |
| **ADCS RPC Relay** | ntlmrelayx.py --target rpc://ca | ❌ |
| **ESC8 - ADCS Relay** | ntlmrelayx.py con templates | ❌ |

---

## 5. Escalada de Privilegios

### 5.1 Abuso de Permisos ACL

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **GenericAll Abuse** | PowerView, BloodHound | ❌ |
| **GenericWrite Abuse** | PowerView, targetedKerberoast | ❌ |
| **WriteOwner Abuse** | PowerView, Set-DomainObjectOwner | ❌ |
| **WriteDACL Abuse** | PowerView, Add-DomainObjectAcl | ❌ |
| **AllExtendedRights Abuse** | PowerView, Force Change Password | ❌ |

### 5.2 Ataques de Grupo

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **DNSAdmins Privilege Escalation** | dnscmd, DLL injection | ❌ |
| **Backup Operators Abuse** | diskshadow, robocopy | ❌ |
| **Exchange Windows Permissions** | PrivExchange, PowerShell | ❌ |
| **Group Policy Creator Owners** | SharpGPOAbuse | ❌ |

### 5.3 Vulnerabilidades Específicas

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **PrintNightmare (CVE-2021-34527)** | cube0x0's exploit | ✅ (CVE-PrintNightmare.md) |
| **noPac (CVE-2021-42278/42287)** | sam-the-admin, noPac.py | ✅ (noPac.md) |
| **ZeroLogon (CVE-2020-1472)** | zerologon.py | ✅ (CVE-ZeroLogon.md) |
| **MS14-068 (CVE-2014-6324)** | goldenPac.py, kekeo | ✅ (CVE-MS14-068.md) |

---

## 6. Persistencia

### 6.1 Técnicas de Persistencia en AD

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Golden Ticket Persistence** | mimikatz, ticketer.py | ✅ (Golden-Ticket.md) |
| **Silver Ticket Persistence** | mimikatz, ticketer.py | ✅ (Silver-Ticket.md) |
| **Skeleton Key** | mimikatz | ❌ |
| **DCShadow** | mimikatz | ❌ |
| **SID History Injection** | mimikatz, SIDHistory | ❌ |

### 6.2 Persistencia via ADCS

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Malicious Certificate Templates** | Certify, certipy | ❌ |
| **Certificate Theft** | mimikatz, SharpDPAPI | ❌ |
| **Shadow Credentials** | whisker, pywhisker | ❌ |

### 6.3 Persistencia en Objetos AD

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **AdminSDHolder Abuse** | PowerView, Set-DomainObjectOwner | ❌ |
| **GPO Backdoors** | SharpGPOAbuse, PowerSploit | ❌ |
| **ACL Backdoors** | PowerView, Add-DomainObjectAcl | ❌ |

---

## 7. Movimiento Lateral

### 7.1 Técnicas de Autenticación

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Pass-the-Hash** | mimikatz, crackmapexec | ✅ (PassTheHash.md) |
| **Pass-the-Ticket** | mimikatz, getTGT.py | ✅ (Impersonation-Attacks.md, Golden-Ticket.md, Silver-Ticket.md) |
| **Pass-the-Key** | Rubeus, mimikatz | ✅ (Impersonation-Attacks.md) |
| **Overpass-the-Hash** | Rubeus, mimikatz | ✅ (Impersonation-Attacks.md) |

### 7.2 Ejecución Remota

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **WMI Execution** | wmiexec.py, Invoke-WmiCommand | ❌ |
| **DCOM Execution** | dcomexec.py, MMC20.Application | ❌ |
| **SMB Execution** | smbexec.py, psexec.py | ❌ |
| **WinRM Execution** | evil-winrm, Invoke-Command | ❌ |
| **SSH Execution** | ssh, OpenSSH for Windows | ❌ |

### 7.3 Técnicas de NetExec/CrackMapExec

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **CrackMapExec SMB** | crackmapexec smb | ✅ (Lateral-nxc.md) |
| **CrackMapExec WinRM** | crackmapexec winrm | ✅ (Lateral-nxc.md) |
| **CrackMapExec SSH** | crackmapexec ssh | ❌ |
| **CrackMapExec MSSQL** | crackmapexec mssql | ❌ |
| **CrackMapExec LDAP** | crackmapexec ldap | ❌ |

---

## 8. Ataques de Certificados (ADCS)

### 8.1 Enumeración ADCS

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Certify Enumeration** | Certify.exe find | ❌ |
| **Certipy Enumeration** | certipy find | ❌ |
| **ADCS Template Audit** | ADCSTemplate, PSPKIAudit | ❌ |

### 8.2 Vulnerabilidades ADCS

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **ESC1 - Misconfigured Templates** | Certify, certipy | ❌ |
| **ESC2 - Any Purpose EKU** | Certify, certipy | ❌ |
| **ESC3 - Enrollment Agent Templates** | Certify, certipy | ❌ |
| **ESC4 - Vulnerable Template ACL** | Certify, certipy | ❌ |
| **ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2** | Certify, certipy | ❌ |
| **ESC7 - Vulnerable CA ACL** | Certify, certipy | ❌ |
| **ESC8 - NTLM Relay to ADCS** | ntlmrelayx.py, Certify | ❌ |

### 8.3 Certificate-Based Attacks

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Pass-the-Certificate** | Rubeus, gettgtpkinit.py | ❌ |
| **UnPAC the Hash** | gettgtpkinit.py, getnthash.py | ❌ |
| **Shadow Credentials** | whisker, pywhisker | ❌ |

---

## 9. Ataques de Delegación

### 9.1 Unconstrained Delegation

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Printer Bug + Unconstrained** | printerbug.py, Rubeus monitor | ✅ (Unconstrained-Delegation.md) |
| **Ticket Extraction** | Rubeus dump, mimikatz | ✅ (Unconstrained-Delegation.md) |
| **Computer Account Takeover** | Rubeus, mimikatz | ✅ (Unconstrained-Delegation.md) |

### 9.2 Constrained Delegation

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **S4U2Self Abuse** | Rubeus s4u, getST.py | ✅ (Constrained-Delegation.md, S4U2Self-S4U2Proxy-Abuse.md) |
| **S4U2Proxy Abuse** | Rubeus s4u, getST.py | ✅ (Constrained-Delegation.md, S4U2Self-S4U2Proxy-Abuse.md) |
| **Protocol Transition** | Rubeus, mimikatz | ✅ (Constrained-Delegation.md) |

### 9.3 Resource-Based Constrained Delegation

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **RBCD via GenericWrite** | PowerMad, Rubeus | ✅ (RBCD.md) |
| **RBCD via GenericAll** | PowerMad, Rubeus | ✅ (RBCD.md) |
| **Machine Account Quotas** | PowerMad, addcomputer.py | ❌ |

---

## 10. Ataques Post-Explotación

### 10.1 Extracción de Secretos

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **NTDS.dit Extraction** | secretsdump.py, vssadmin | ✅ (NTDS-dit-Extraction.md) |
| **LSA Secrets** | secretsdump.py, mimikatz | ❌ |
| **Cached Credentials** | secretsdump.py, mimikatz | ❌ |
| **DPAPI Secrets** | mimikatz, SharpDPAPI | ❌ |

### 10.2 Análisis y Pivoting

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **Domain Trust Enumeration** | PowerView, BloodHound | ❌ |
| **Foreign Security Principals** | PowerView, BloodHound | ❌ |
| **Cross-Domain Attacks** | mimikatz, Rubeus | ❌ |
| **Forest Trust Abuse** | mimikatz, Golden Ticket | ❌ |

### 10.3 Técnicas de Evasión

| Técnica | Herramientas | Estado en Repo |
|---------|-------------|----------------|
| **AMSI Bypass** | PowerShell, .NET reflection | ❌ |
| **ETW Patching** | mimikatz, manual patching | ❌ |
| **Process Injection** | Cobalt Strike, manual injection | ❌ |
| **Living off the Land** | Built-in Windows tools | ❌ |

---

## 📊 Estado Actual del Repositorio

### ✅ Técnicas ya Documentadas (45)
- AS-REP Roasting
- Kerberoasting  
- Pass-the-Hash
- Pass-the-Ticket
- SMB Relay Attacks
- RBCD (Resource-Based Constrained Delegation)
- BloodHound Usage
- PrintNightmare (CVE-2021-34527)
- noPac (CVE-2021-42278/42287)
- ZeroLogon (CVE-2020-1472)
- MS14-068 (CVE-2014-6324)
- Enumeration via RPC, LDAP, Users, SMB, DNS, NTP
- User Enumeration via Kerberos
- Anonymous Logon techniques
- Lateral Movement with NetExec
- Coercion attacks (PrinterBug, PetitPotam, DFSCoerce)
- Brute Force attacks (Kerberos, LDAP)
- Impersonation techniques overview
- Unconstrained Delegation
- Constrained Delegation
- S4U2Self/S4U2Proxy Abuse
- Golden Ticket Attacks & Persistence
- Silver Ticket Attacks & Persistence
- DCSync Attack
- NTDS.dit Extraction
- Password Spraying

### ❌ Técnicas Pendientes de Documentar (>77)

#### 🔴 Prioridad Alta (Técnicas Fundamentales):
1. **Golden/Silver Ticket Attacks**
2. **NTDS.dit Extraction y DCSync**
3. **ADCS Vulnerabilities (ESC1-ESC8)**
4. **Unconstrained/Constrained Delegation**
5. **Password Spraying y Credential Stuffing**
6. **WMI/DCOM/WinRM Execution**
7. **DNS Admin Privilege Escalation**

#### 🟡 Prioridad Media (Técnicas Especializadas):
1. **Shadow Credentials**
2. **Certificate-based attacks**
3. **ACL Abuse techniques**
4. **Cross-domain/forest attacks**
5. **DPAPI and LSA Secrets**
6. **Group Policy abuse**

#### 🟢 Prioridad Baja (Técnicas Avanzadas):
1. **DCShadow**
2. **Skeleton Key**
3. **Advanced persistence techniques**
4. **Evasion techniques**

---

## 🎯 Próximos Pasos Recomendados

1. **Seleccionar técnicas de Prioridad Alta** para documentar primero
2. **Mantener formato consistente** con archivos existentes
3. **Incluir ejemplos prácticos** y comandos específicos
4. **Agregar secciones de detección y mitigación**
5. **Crear referencias cruzadas** entre técnicas relacionadas

---

**Documento creado:** Julio 2024  
**Técnicas identificadas:** ~150+ técnicas de AD pentesting  
**Estado actual:** 45 documentadas, >77 pendientes  
**Última actualización:** Agosto 2024  
**Fuentes:** Recopilación de recursos estándar de AD pentesting  