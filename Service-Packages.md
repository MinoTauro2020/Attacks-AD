# 📦 Definición de Service Packages - TTPs por Nivel

---

## 🎯 Resumen Ejecutivo

Este documento define la organización específica de técnicas por pack de servicio, mapeando cada TTP del repositorio a su nivel de complejidad y prerrequisitos de acceso.

---

## 🔰 Pack 1 - Fundamentos (TTPs Básicos)

### 🎯 Objetivo
Establecer base de seguridad mediante la detección de vectores de ataque más comunes y accesibles.

### 📋 Técnicas Incluidas

#### 1.1 Reconocimiento y Enumeración Básica
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Enumeración SMB** | EnumUsers.md | 🟢 Baja | Conectividad de red |
| **Enumeración LDAP** | BruteForce-Ldap.md | 🟢 Baja | Puerto 389/636 |
| **Enumeración RPC** | Enum-Rpcclient.md | 🟢 Baja | Puerto 135/445 |
| **Anonymous Logon** | Anonymous-Logon-Guest.md | 🟢 Baja | Acceso SMB |

#### 1.2 Ataques de Credenciales Básicos
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **AS-REP Roasting** | As-Rep-Roasting.md | 🟡 Media | Lista de usuarios |
| **Kerberoasting** | Kerberoasting.md | 🟡 Media | Credenciales de dominio |
| **BruteForce Kerberos** | BruteForce-Kerberos.md | 🟢 Baja | Conectividad KDC |
| **BruteForce LDAP** | BruteForce-Ldap.md | 🟢 Baja | Conectividad LDAP |

#### 1.3 Ataques de Relay Básicos
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **SMB Relay Básico** | SmbRelay-Attack.md | 🟡 Media | Posición de red |
| **Responder + NTLM Relay** | Responder-Ntlmrelay.md | 🟡 Media | Segmento de red |

### 🎯 Objetivos de Detección Pack 1
- ✅ Detectar enumeración masiva de usuarios
- ✅ Alertar sobre solicitudes AS-REP anómalas  
- ✅ Identificar ataques de fuerza bruta
- ✅ Detectar relay attacks básicos

### 📊 Herramientas Principales
- **Enumeración**: enum4linux, ldapsearch, rpcclient
- **Kerberos**: GetNPUsers.py, GetUserSPNs.py, kerbrute
- **Relay**: ntlmrelayx.py, Responder
- **Análisis**: BloodHound (básico)

### 🛡️ Hardening Recomendado
- SMB Signing obligatorio
- Desactivar SMBv1
- Configurar preautenticación Kerberos
- Monitoring de eventos 4624, 4625, 4768, 4769

---

## ⚡ Pack 2 - Intermedio (TTPs Avanzados)

### 🎯 Objetivo
Técnicas sofisticadas que requieren conocimiento avanzado o acceso privilegiado inicial.

### 📋 Técnicas Incluidas

#### 2.1 Ataques Kerberos Avanzados
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Unconstrained Delegation** | Unconstrained-Delegation.md | 🔴 Alta | Admin en servidor |
| **Constrained Delegation** | Constrained-Delegation.md | 🔴 Alta | Control de servicios |
| **RBCD Abuse** | RBCD.md | 🔴 Alta | GenericWrite/GenericAll |
| **S4U2Self/S4U2Proxy** | S4U2Self-S4U2Proxy-Abuse.md | 🔴 Alta | Delegación configurada |

#### 2.2 Ataques de Tickets
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Pass-the-Hash** | PassTheHash.md | 🟡 Media | Hash NTLM |
| **Pass-the-Ticket** | PassTheHash.md | 🟡 Media | Ticket válido |
| **Overpass-the-Hash** | PassTheHash.md | 🔴 Alta | Hash + DC access |

#### 2.3 Relay Attacks Avanzados
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Coerción de Auth** | Coerce.md | 🔴 Alta | Posición privilegiada |
| **PrinterBug/PetitPotam** | Coerce.md | 🔴 Alta | Conectividad específica |
| **NTLM Relay Multi-protocolo** | Diferencias-ntlmrelayx-vs-Coercion.md | 🔴 Alta | Control de tráfico |

#### 2.4 Vulnerabilidades Específicas
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **ZeroLogon** | CVE-ZeroLogon.md | 🔴 Alta | Conectividad DC |
| **PrintNightmare** | CVE-PrintNightmare.md | 🔴 Alta | Spooler habilitado |
| **noPac** | noPac.md | 🔴 Alta | Credenciales válidas |

### 🎯 Objetivos de Detección Pack 2
- ✅ Detectar abuso de delegaciones Kerberos
- ✅ Identificar ataques de coerción
- ✅ Alertar sobre vulnerabilidades críticas
- ✅ Monitorear ataques de relay avanzados

### 📊 Herramientas Principales
- **Kerberos**: Rubeus, getST.py, findDelegation.py
- **Relay Avanzado**: ntlmrelayx.py (targets múltiples)
- **Coerción**: printerbug.py, PetitPotam.py
- **CVEs**: Scripts específicos por vulnerabilidad

### 🛡️ Hardening Recomendado
- Auditoría de delegaciones configuradas
- Parches críticos actualizados
- Monitoreo avanzado de Kerberos (4769, 4770)
- Network segmentation

---

## 🎯 Pack 3 - Experto (TTPs Especializados)

### 🎯 Objetivo
Técnicas de persistencia, evasión avanzada y ataques a sistemas especializados como mainframes.

### 📋 Técnicas Incluidas

#### 3.1 Persistencia y Tickets Dorados
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Golden Ticket** | A documentar | 🔴 Muy Alta | KRBTGT hash |
| **Silver Ticket** | A documentar | 🔴 Muy Alta | Service account hash |
| **Diamond Ticket** | A documentar | 🔴 Muy Alta | TGT válido |
| **Skeleton Key** | A documentar | 🔴 Muy Alta | Control total DC |

#### 3.2 Ataques Avanzados AD
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **DCShadow** | A documentar | 🔴 Muy Alta | Admin de dominio |
| **DCSync** | A documentar | 🔴 Muy Alta | Privilegios replicación |
| **SID History Injection** | A documentar | 🔴 Muy Alta | Admin privilegios |

#### 3.3 Ataques ADCS (Certificate Services)
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **ESC1-8 Attacks** | A documentar | 🔴 Muy Alta | Acceso a CA |
| **Certificate Template Abuse** | A documentar | 🔴 Muy Alta | Modificar templates |
| **CA Persistence** | A documentar | 🔴 Muy Alta | Control de CA |

#### 3.4 Mainframes z/OS
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **z/OS Enumeration** | Mainframe-zOS-Attacks.md | 🔴 Muy Alta | Acceso mainframe |
| **TSO/ISPF Attacks** | Mainframe-zOS-Attacks.md | 🔴 Muy Alta | Credenciales TSO |
| **RACF Bypass** | Mainframe-zOS-Attacks.md | 🔴 Muy Alta | Conocimiento específico |
| **DB2 Privilege Escalation** | Mainframe-zOS-Attacks.md | 🔴 Muy Alta | Acceso DB2 |

#### 3.5 Movimiento Lateral Avanzado
| TTP | Archivo Referencia | Complejidad | Acceso Requerido |
|-----|-------------------|-------------|------------------|
| **Lateral Movement (nxc)** | Lateral-nxc.md | 🔴 Alta | Credenciales múltiples |
| **Token Impersonation** | A documentar | 🔴 Muy Alta | Process privileges |
| **COM/DCOM Abuse** | A documentar | 🔴 Muy Alta | Admin local |

### 🎯 Objetivos de Detección Pack 3
- ✅ Detectar persistencia avanzada
- ✅ Identificar ataques a infraestructura crítica
- ✅ Monitorear ataques a mainframes
- ✅ Alertar sobre evasión de controles

### 📊 Herramientas Especializadas
- **Tickets**: mimikatz, ticketer.py, Rubeus avanzado
- **ADCS**: Certify, ESC tools
- **Mainframes**: Nmap z/OS scripts, herramientas específicas
- **Evasión**: Herramientas OPSEC-safe

### 🛡️ Hardening Avanzado
- Monitoreo de eventos críticos (4672, 4673, 4674)
- Hardening de Certificate Services
- Seguridad específica de mainframes
- Zero Trust architecture

---

## 📊 Matriz de Prerrequisitos

### Por Nivel de Acceso Cliente

| Pack | Sin Máquina (SIEM Only) | Con Máquina Limitada | Laboratorio Completo |
|------|-------------------------|----------------------|----------------------|
| **Pack 1** | ✅ Hunting básico | ✅ Ejecución básica | ✅ Ejecución completa |
| **Pack 2** | ⚠️ Hunting limitado | ✅ Ejecución mayoría | ✅ Ejecución completa |
| **Pack 3** | ❌ Solo IOC hunting | ⚠️ Técnicas limitadas | ✅ Ejecución completa |

### Duración Estimada por Escenario

| Pack | SIEM Only | Máquina Limitada | Lab Completo |
|------|-----------|------------------|--------------|
| **Pack 1** | 2-3 semanas | 2-4 semanas | 3-4 semanas |
| **Pack 2** | 3-4 semanas | 4-6 semanas | 5-7 semanas |
| **Pack 3** | 2-3 semanas | 4-6 semanas | 6-8 semanas |

---

## 🔄 Metodología de Escalamiento

### Criterios Objetivos de Avance

#### Pack 1 → Pack 2
- ✅ ≥70% de técnicas básicas detectadas
- ✅ Logs de AD configurados y monitoreados
- ✅ Controles básicos de red implementados
- ✅ Equipo SOC entrenado en TTPs básicos

#### Pack 2 → Pack 3
- ✅ ≥80% de técnicas intermedias detectadas
- ✅ Herramientas de monitoreo avanzado activas
- ✅ Parches críticos aplicados
- ✅ Arquitectura de seguridad revisada

### Plan de Remediación por Pack

#### Técnicas No Detectadas Pack 1
1. **Enumeración SMB**: Implementar monitoring NetBIOS
2. **AS-REP Roasting**: Configurar preauth obligatoria
3. **Kerberoasting**: Passwords complejos para service accounts
4. **SMB Relay**: SMB signing + network segmentation

#### Técnicas No Detectadas Pack 2
1. **Delegaciones**: Auditoría y restricción de delegaciones
2. **CVEs**: Programa de patching acelerado
3. **Relay Avanzado**: Implementar LDAP signing + EPA
4. **Coerción**: Filtrado de tráfico específico

#### Técnicas No Detectadas Pack 3
1. **Golden Ticket**: Rotación KRBTGT + monitoreo eventos 4624
2. **DCShadow**: Monitoreo cambios en AD schema
3. **ADCS**: Hardening de templates + auditoría
4. **Mainframes**: Implementar logging específico z/OS

---

## 📚 Referencias Técnicas

### Documentación por Pack
- **Pack 1**: Ver archivos básicos en repositorio
- **Pack 2**: Ver archivos avanzados + CVEs
- **Pack 3**: Combinar todas las técnicas + mainframes

### Hunting Queries
- [PrintNightmare-Hunting.md](PrintNightmare-Hunting.md) - Queries específicas
- Custom queries por pack en desarrollo

### Mitigaciones
- [SmbRelay-Mitigacion.md](SmbRelay-Mitigacion.md) - Hardening SMB
- Documentos de defensa específicos por técnica

---

*Actualizado: Agosto 2024*  
*Autor: [MinoTauro2020](https://github.com/MinoTauro2020)*