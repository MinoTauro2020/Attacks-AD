# Attacks-AD

Repositorio de referencia y ayuda rápida sobre ataques, técnicas y hardening en Active Directory y Mainframes z/OS, especialmente centrado en suplantación de identidad (impersonation), ataques de Kerberos, abuso de servicios y seguridad de sistemas mainframe.

## Contenido

### 📋 Documentos Principales
- **AD-Tecnicas-Completas.md**: 🆕 **Compilación completa de +150 técnicas de AD pentesting** organizadas por categorías con estado de documentación.
- **Impersonation-Attacks.md**: Índice práctico de técnicas de suplantación en Active Directory.
- **Impersonation-Explain.md**: Tabla detallada de explicación, falsos positivos y verificación para cada técnica.
- **Impersonation-Resume.md**: Resumen visual rápido de técnicas y herramientas principales.

### 📦 Sistema de Paquetización para Clientes
- **Client-Packaging-Methodology.md**: 🆕 **Metodología completa de paquetización** para organizar servicios de ciberseguridad en packs escalables.
- **Service-Packages.md**: 🆕 **Definición de Service Packages** - TTPs organizados por nivel (Pack 1: Básico, Pack 2: Intermedio, Pack 3: Experto).
- **Client-Scenarios-Implementation.md**: 🆕 **Guía de implementación por escenarios** - Metodologías específicas según acceso del cliente (máquina dedicada vs. solo SIEM/XDR).

### 🛠️ Técnicas Específicas
- **Anonymous-Logon-Guest.md**: Cómo bloquear acceso de Anonymous Logon y Guest en Windows/AD.
- **As-Rep-Roasting.md**: Detalles, detección y mitigación de AS-REP Roasting.
- **Kerberoasting.md**: Técnica de solicitud y crackeo de tickets TGS.
- **PassTheHash.md**: Autenticación usando hashes NTLM.

#### 🎫 Ataques de Delegación Kerberos
- **Unconstrained-Delegation.md**: Abuso de delegación no restringida y extracción de TGT.
- **Constrained-Delegation.md**: Explotación de delegación restringida con S4U2Self/S4U2Proxy.
- **RBCD.md**: Resource-Based Constrained Delegation abuse.
- **S4U2Self-S4U2Proxy-Abuse.md**: Abuso de extensiones S4U y Bronze Bit attacks.

#### 🔧 Otras Técnicas
- **CVE-PrintNightmare.md**: Explotación de PrintNightmare.
- **noPac.md**: Explotación de vulnerabilidades noPac.
- **SmbRelay-Attack.md**: Ataques de relay SMB/NTLM.
- **Coerce.md**: Técnicas de coerción de autenticación.
- **BloodHound-py.md**: Uso de BloodHound para análisis de AD.
- **Lateral-nxc.md**: Movimiento lateral con NetExec.

### 🖥️ Mainframe Security
- **Mainframe-zOS-Attacks.md**: 🆕 **Guía completa de ataques a mainframes z/OS** incluyendo técnicas de red team, CVEs, hardening y parches.

## ¿Para qué sirve este repo?

- Para equipos de blue team y administradores que quieran reforzar la seguridad de AD y mainframes ante ataques reales y simulados.
- Para pentesters/red teamers que necesiten consultar referencias y comandos en ataques de suplantación y sistemas mainframe.
- Para especialistas en seguridad de mainframes z/OS que busquen técnicas de hardening y mitigación.
- **Para consultores y empresas de ciberseguridad** que necesiten estructurar servicios escalables mediante el sistema de paquetización por niveles de complejidad y acceso del cliente.


---

Actualizado a: Julio 2024  
Autor: [MinoTauro2020](https://github.com/MinoTauro2020)
