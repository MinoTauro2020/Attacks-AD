# 🛡️ SMB Relay: Limitaciones Modernas, Protecciones y Consideraciones de Red Team / Blue Team

**By: Hiper experto Red Team | Purple Team | Threat Hunter | Blue Team | Threat Intelligence**

---

## 1️⃣ Limitaciones clave del ataque SMB Relay en entornos modernos

### 🔒 **SMB Signing (Firmado SMB)**
- **¿Qué es?**  
  Mecanismo de integridad que previene la manipulación de paquetes SMB.
- **Impacto:**  
  Si está activado y requerido, **el relay SMB tradicional no es posible**: el atacante no puede firmar los paquetes relayados y la autenticación es rechazada.
- **Estado actual:**  
  - En Windows 10/2016+ y superiores, habilitado por defecto en DCs y servidores sensibles.
  - Aún hay appliances, legacy, impresoras o NAS sin signing.

---

### 🔁 **Protección Loopback/NTLM Self-Relay**
- **¿Qué es?**  
  Previene que una máquina acepte su propio hash NTLM relayado.
- **Impacto:**  
  - **No puedes relayar una autenticación de la máquina contra sí misma** (ni como usuario ni como máquina).
  - Limita ataques de “self-relay” y explotación local directa.
- **Estado actual:**  
  - Activo por defecto desde Windows 10/2016+ y parches recientes.

---

### 🛡️ **Protección NTLM Reflection y Extended Protection for Authentication (EPA)**
- **¿Qué es?**  
  - Protecciones adicionales para evitar relay de NTLM en servicios HTTP, LDAP, etc.
  - EPA añade información de canal seguro en la autenticación, haciendo el relay mucho más difícil.
- **Impacto:**  
  - Servicios modernos (IIS, Exchange, LDAP signing, etc.) suelen tener EPA o NTLM reflection protection.
  - **Se reduce dramáticamente la superficie de ataque** para relay tradicional.

---

### 🖥️ **Necesidad de múltiples objetivos/víctimas**
- **¿Por qué?**  
  - Solo puedes relayar autenticaciones NTLM de una máquina a *otra* máquina diferente.
  - **No puedes relayar a la misma máquina** (por loopback protection).
  - Necesitas hosts adicionales sin SMB signing o con servicios legacy para tener éxito.
- **Implicación Red Team:**  
  - Tu archivo de objetivos (`targets.txt`) debe tener **varios hosts vulnerables**.
  - Los ataques más efectivos se dirigen a impresoras, appliances, NAS, servidores legacy… no tanto a DCs modernos.

---

### 🔗 **SMB2/3 Enforcement & Legacy**
- **¿Qué es?**  
  - SMB2/3 requiere firmar por defecto; SMB1 es vulnerable pero está deshabilitado por defecto en versiones modernas.
- **Impacto:**  
  - Menos superficie de ataque en entornos actuales.
  - **La explotación suele centrarse en sistemas legacy o mal configurados.**

---

## 2️⃣ Bypass y vectores alternativos

- **LDAP relay:**  
  Muchos entornos permiten relay a LDAP (sin signing), lo que abre la puerta a abusos como RBCD, LAPS, Shadow Credentials, etc.
- **HTTP relay:**  
  Servicios web internos legacy pueden ser vulnerables si no usan EPA.
- **Ataques de coerción (PetitPotam, DFSCoerce, etc.):**  
  Permiten forzar autenticaciones desde víctimas hacia el relay.

---

## 3️⃣ Implicaciones para Red Team

- **Recon**:  
  Escanea constantemente para descubrir hosts sin SMB signing y servicios legacy.
- **Objetivos preferidos:**  
  Impresoras, NAS, appliances, servidores de archivos, sistemas legacy.
- **Ataques modernos:**  
  Enfócate en relay a LDAP, HTTP y abusos post-explotación (RBCD, Shadow Credentials, ADCS, etc.).

---

## 4️⃣ Blue Team / Threat Hunter

- **Auditoría continua de SMB signing y configuración de NTLM/EPA.**
- **Alertas sobre intentos de relay y autenticaciones fallidas en múltiples hosts.**
- **Monitoriza cambios en objetos AD críticos tras relays (msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-KeyCredentialLink, LAPS/gMSA, etc.).**
- **Segmenta y aísla sistemas legacy siempre que sea posible.**

---

## 5️⃣ Threat Intelligence

- **Los APTs y ransomware buscan sistemáticamente activos sin SMB signing.**
- **El enfoque del adversario se mueve a protocolos/servicios menos protegidos (LDAP, HTTP, RPC).**
- **La defensa exige visibilidad total, hardening y monitorizacion proactivo.**

---

## 6️⃣ Resumen visual

| Protección            | ¿Qué impide?                                | ¿Cómo lo evitas?                      |
|-----------------------|---------------------------------------------|----------------------------------------|
| SMB Signing           | Relay SMB tradicional                       | Apunta a hosts sin signing o legacy    |
| Loopback NTLM         | Relay a la misma máquina                    | Relaya a otro host diferente           |
| Extended Protection   | Relay a servicios HTTP/LDAP modernos        | Busca servicios sin EPA                |
| SMB2/3 Enforcement    | Relay SMB a sistemas modernos               | Explota SMB1/legacy, appliances        |

---

