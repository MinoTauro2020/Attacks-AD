# Funcionamiento de ataques de coerción (Coerce, PetitPotam, DFSCoerce) y Mitigaciones

> **Resumen:**  
> Explicación experta multidisciplinar sobre el funcionamiento de los ataques de coerción (coerce attacks) contra entornos Windows/AD: cómo funcionan, condiciones, riesgos, mitigaciones y rutas rápidas para endurecimiento. Incluye visión Red Team, Blue Team, Purple Team, Threat Hunter y Threat Intelligence.

---

## Índice

1. [¿Qué son los ataques de coerción (Coerce, PetitPotam, etc.)?](#1-qué-son-los-ataques-de-coerción-coerce-petitpotam-etc)
2. [¿Por qué existen y cómo funcionan?](#2-por-qué-existen-y-cómo-funcionan)
3. [¿Por qué son vulnerables los protocolos RPC/DCERPC?](#3-por-qué-son-vulnerables-los-protocolos-rpcdcerpc)
4. [¿Qué obtiene el atacante?](#4-qué-obtiene-el-atacante)
5. [¿Por qué siguen funcionando estos ataques?](#5-por-qué-siguen-funcionando-estos-ataques)
6. [Condiciones para ser vulnerable](#6-condiciones-para-ser-vulnerable)
7. [Vectores y protocolos típicos explotados](#7-vectores-y-protocolos-típicos-explotados)
8. [Funcionamiento del ataque paso a paso](#8-funcionamiento-del-ataque-paso-a-paso)
9. [Mitigaciones recomendadas](#9-mitigaciones-recomendadas)
10. [Deshabilitar servicios vulnerables (clave)](#10-deshabilitar-servicios-vulnerables-clave)
11. [Resumen visual del ataque](#11-resumen-visual-del-ataque)
12. [Resumen de mitigaciones](#12-resumen-de-mitigaciones)
13. [Cómo aplicar las principales medidas en Windows](#13-cómo-aplicar-las-principales-medidas-en-windows)
14. [Resumen rápido de rutas](#14-resumen-rápido-de-rutas)

---

## 1. ¿Qué son los ataques de coerción (Coerce, PetitPotam, etc.)?

| Técnica         | Descripción                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------|
| Coerción NTLM   | Abusa de servicios/funciones de Windows para forzar a un host (ej: DC) a autenticarse vía NTLM contra un servidor controlado por el atacante. |
| Ejemplos        | PetitPotam, Coercer, DFSCoerce, PrinterBug, ShadowCoerce, EFSRPC abuse, etc.               |

---

## 2. ¿Por qué existen y cómo funcionan?

| Motivo             | Explicación                                       |
|--------------------|--------------------------------------------------|
| RPC/DCERPC         | Servicios Windows exponen funciones remotas que pueden ser abusadas para “coaccionar” autenticaciones. |
| Falta de control   | Muchas funciones aceptan rutas UNC arbitrarias, permitiendo al atacante indicar su propio servidor.     |

---

## 3. ¿Por qué son vulnerables los protocolos RPC/DCERPC?

| Motivo              | Detalle                                                  |
|---------------------|----------------------------------------------------------|
| Diseño legacy       | Los protocolos fueron diseñados antes de amenazas modernas y confían en llamadas autenticadas mínimas. |
| Exposición excesiva | Servicios como EFSRPC, Print Spooler, DFS, VSS, FSRVP, EventLog, etc., están activos por defecto o en muchos roles. |
| Falta de restricciones | Algunos servicios permiten coerción incluso sin privilegios elevados o con sesiones nulas. |

---

## 4. ¿Qué obtiene el atacante?

| Escenario         | Resultado                                       |
|-------------------|------------------------------------------------|
| Captura de hash   | Hash NTLM de la máquina víctima (ej: del DC).  |
| Relay de hash     | Posibilidad de relay a otros servicios internos si signing no está activo. |
| Contraseña débil  | Crackeo de NTLMv1 si está habilitado.          |
| Movimiento lateral| Usar el hash capturado para pivotar o elevar privilegios. |

---

## 5. ¿Por qué siguen funcionando estos ataques?

| Motivo                             | Explicación                                          |
|------------------------------------|-----------------------------------------------------|
| Servicios activos por defecto      | EFSRPC, Print Spooler, DFS, etc., habilitados en muchos entornos. |
| NTLM aún presente                  | NTLM sigue habilitado y necesario para compatibilidad.|
| Falta de parcheo/hardening         | Muchas organizaciones no aplican mitigaciones Microsoft recomendadas. |
| Conciencia limitada                | El riesgo es conocido sobre todo en pentesting/red team, pero no siempre en IT/Ops. |

---

## 6. Condiciones para ser vulnerable

| Condición                       | Riesgo que implica                                      |
|---------------------------------|---------------------------------------------------------|
| Servicios vulnerables activos   | Coerción posible (EFSRPC, Print Spooler, DFS, etc.)     |
| NTLMv1 habilitado               | Hashes fáciles de crackear.                             |
| NTLMv2 + contraseñas débiles    | Crackeo posible si la contraseña es débil.              |
| SMB/LDAP/HTTP sin signing       | Permiten relay de autenticación NTLM.                   |
| Usuarios con privilegios altos  | Coerción de cuentas privilegiadas aumenta el impacto.   |

---

## 7. Vectores y protocolos típicos explotados

| Protocolo/Servicio | Abusado por             | Descripción breve                                      |
|--------------------|-------------------------|--------------------------------------------------------|
| MS-EFSR (EFSRPC)   | PetitPotam, Coercer     | Coerción a través de funciones de cifrado de archivos. |
| MS-RPRN (Print Spooler) | PrinterBug, Coercer | Coerción vía gestión de impresoras remotas.            |
| MS-DFSNM (DFS)     | DFSCoerce, Coercer      | Coerción vía gestión de espacios de nombres DFS.       |
| MS-FSRVP (Shadow Copy) | Coercer             | Coerción vía copias de seguridad de volúmenes.         |
| MS-EVEN (EventLog) | Coercer                 | Coerción a través de logs de eventos remotos.          |

---

## 8. Funcionamiento del ataque paso a paso

1. El atacante ejecuta Coercer/PetitPotam/DFSCoerce y apunta a la víctima.
2. La herramienta fuerza a la víctima a realizar una autenticación NTLM (challenge/response) contra un servidor controlado por el atacante.
3. El atacante captura el hash NTLM o lo relayea a otro servicio interno.
4. Si la víctima es un DC o usuario con privilegios, el impacto es crítico (movimiento lateral, escalada, persistencia).

---

## 9. Mitigaciones recomendadas

| Mitigación                            | ¿Qué previene?                              |
|----------------------------------------|---------------------------------------------|
| Parchear sistemas y servicios          | Elimina vectores conocidos de coerción.     |
| Deshabilitar servicios vulnerables     | Elimina la posibilidad de coerción por ese vector. |
| Habilitar SMB/LDAP Signing             | Bloquea relay NTLM en SMB/LDAP.             |
| Deshabilitar NTLMv1                    | Elimina hashes débiles y cracking trivial.  |
| Forzar solo NTLMv2                     | Dificulta el cracking offline.              |
| Contraseñas robustas                   | Dificulta cracking NTLMv2.                  |
| Segmentar/red endurecida               | Limita el alcance del atacante.             |
| Migrar servicios a Kerberos            | Reduce/elimina uso de NTLM.                 |

---

## 10. Deshabilitar servicios vulnerables (clave)

### Pasos para Print Spooler (ejemplo)

1. Ejecuta en el DC/servidor:
   ```powershell
   Stop-Service -Name Spooler
   Set-Service -Name Spooler -StartupType Disabled
   ```
2. Aplica GPO para deshabilitar Print Spooler remotamente:
   - `gpedit.msc` → Configuración del equipo → Plantillas administrativas → Impresoras → Permitir administración de impresoras desde conexiones remotas → **Deshabilitado**

### Otros servicios:
- **EFSRPC**: Solo habilitar en servidores que lo requieran.
- **DFS, FSRVP, EventLog remoto**: Limitar el acceso con ACLs o deshabilitar funciones remotas si es posible.

---

## 11. Resumen visual del ataque

```
Atacante fuerza autenticación (PetitPotam, Coercer, etc.)
      ↓
Víctima intenta autenticarse (NTLM) contra servidor del atacante
      ↓
El atacante captura/relaya el hash
      ↓
(Posible movimiento lateral, escalada, persistencia)
```

---

## 12. Resumen de mitigaciones

| Medida                           | Impacto principal                        |
|-----------------------------------|------------------------------------------|
| Parcheo y hardening               | Elimina vectores conocidos de coerción.  |
| Deshabilitar Print Spooler, EFSRPC, etc. | Ataque de coerción imposible por ese vector. |
| Desactivar NTLMv1                 | Hashes capturados no se crackean fácil.  |
| Solo NTLMv2 + contraseñas fuertes | Hashes capturados no se crackean.        |
| SMB/LDAP Signing                  | Relay sobre SMB/LDAP no es posible.      |
| Segmentación de red               | Difícil que el atacante llegue a víctimas|
| Kerberos everywhere               | Ataque inservible sin NTLM.              |

---

## 13. Cómo aplicar las principales medidas en Windows

### 🚫 Deshabilitar Print Spooler, EFSRPC, DFS, FSRVP, EventLog remoto

- **Print Spooler**:  
  ```powershell
  Stop-Service -Name Spooler
  Set-Service -Name Spooler -StartupType Disabled
  ```
- **GPO**:  
  - Plantillas administrativas → Impresoras → Deshabilitar administración remota

### 🔒 Habilitar SMB/LDAP Signing

- **SMB:**  
  - `gpedit.msc` → Opciones de seguridad → Microsoft network client/server: Firmar digitalmente las comunicaciones (siempre) → Habilitado
- **LDAP:**  
  - `gpedit.msc` → Opciones de seguridad → Requisitos de firma del servidor LDAP → Requerir firma
  - Registro: `LDAPEnforceChannelBinding`=2

### 🛡️ Deshabilitar NTLMv1 / Forzar solo NTLMv2

- `gpedit.msc` → Opciones de seguridad → Nivel de autenticación LAN Manager → Solo NTLMv2

### 🗝️ Segmentación/red endurecida

- VLANs, firewalls, ACLs, etc.

### 🧢 Migrar servicios a Kerberos

- `gpedit.msc` → Opciones de seguridad → Restringir NTLM

---

## 14. Resumen rápido de rutas

| Medida                | Ubicación/Herramienta                                   |
|-----------------------|--------------------------------------------------------|
| Print Spooler         | Servicios / GPO                                        |
| EFSRPC/DFS/FSRVP      | Servicios / GPO / ACLs                                 |
| NTLMv1/NTLMv2         | gpedit.msc > Opciones de seguridad > Autenticación LAN |
| SMB Signing           | gpedit.msc > Opciones de seguridad > network client    |
| LDAP Signing          | gpedit.msc > Opciones de seguridad > LDAP/NTDS         |
| Segmentación de red   | Infraestructura de red                                 |
| Kerberos/NTLM         | gpedit.msc > Opciones de seguridad > Restringir NTLM   |
| Legacy                | Auditoría manual                                       |

---
