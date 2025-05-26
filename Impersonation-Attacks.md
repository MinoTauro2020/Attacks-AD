# Técnicas de Suplantación/Impersonation en Active Directory – Comandos y Herramientas

---

## Índice de Técnicas

1. [AS-REP Roasting](#1-as-rep-roasting)
2. [Certificate-Based Impersonation (ADCS Abuse)](#2-certificate-based-impersonation-adcs-abuse)
3. [DCShadow Attack](#3-dcshadow-attack)
4. [Golden Ticket Attack](#4-golden-ticket-attack)
5. [Kerberoasting](#5-kerberoasting)
6. [Kerberos Constrained Delegation (KCD) Abuse](#6-kerberos-constrained-delegation-kcd-abuse)
7. [Kerberos Unconstrained Delegation](#7-kerberos-unconstrained-delegation)
8. [Lateral Movement via SMB/Token/Ticket](#8-lateral-movement-via-smbtokenticket)
9. [MSSQL Impersonation (EXECUTE AS)](#9-mssql-impersonation-execute-as)
10. [NTLM/SMB Relay](#10-ntlmsmb-relay)
11. [Overpass-the-Certificate (Pass-the-Cert)](#11-overpass-the-certificate-pass-the-cert)
12. [Overpass-the-Hash (OpTH)](#12-overpass-the-hash-opth)
13. [Pass-the-Hash (PtH)](#13-pass-the-hash-pth)
14. [Pass-the-Key (PTK)](#14-pass-the-key-ptk)
15. [Pass-the-Ticket (PtT)](#15-pass-the-ticket-ptt)
16. [Resource-Based Constrained Delegation (RBCD)](#16-resource-based-constrained-delegation-rbcd)
17. [S4U (Service-for-User) Delegation Abuse](#17-s4u-service-for-user-delegation-abuse)
18. [Shadow Credentials](#18-shadow-credentials)
19. [SID History Injection](#19-sid-history-injection)
20. [Silver Ticket Attack](#20-silver-ticket-attack)
21. [Token Impersonation & Token Stealing](#21-token-impersonation--token-stealing)

---

### Para cada técnica:

#### {Título de técnica}

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Resumen de la técnica                                                                   |
| **Condiciones** | Requisitos para explotación                                                             |

**Herramientas y comandos:**
- **Windows:**  
  - Herramienta  
    ```powershell
    comando
    ```
- **Linux:**  
  - Herramienta  
    ```bash
    comando
    ```

[Volver al índice](#índice-de-técnicas)

---


