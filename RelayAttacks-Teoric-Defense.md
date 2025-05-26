# Funcionamiento de ataques LLMNR/NBT-NS/WPAD/Responder y Mitigaciones

> **Resumen:**  
> Explicación accesible del funcionamiento de los ataques de relay/captura mediante LLMNR, NBT-NS, WPAD y Responder, y cómo proteger tu entorno AD contra ellos. Incluye pasos, condiciones, riesgos, mitigaciones y rutas rápidas para endurecimiento.

---

## Índice

1. [¿Qué son LLMNR, NBT-NS y WPAD?](#1-qué-son-llmnr-nbt-ns-y-wpad)
2. [¿Por qué existen?](#2-por-qué-existen)
3. [¿Por qué son vulnerables?](#3-por-qué-son-vulnerables)
4. [¿Qué obtiene el atacante?](#4-qué-obtiene-el-atacante)
5. [¿Por qué sigue funcionando?](#5-por-qué-sigue-funcionando)
6. [Condiciones para ser vulnerable](#6-condiciones-para-ser-vulnerable)
7. [Por qué NTLMv1 es especialmente peligroso](#7-por-qué-ntlmv1-es-especialmente-peligroso)
8. [¿Y si la máquina solo usa NTLMv2?](#8-y-si-la-máquina-solo-usa-ntlmv2)
9. [Funcionamiento del ataque paso a paso](#9-funcionamiento-del-ataque-paso-a-paso)
10. [Mitigaciones recomendadas](#10-mitigaciones-recomendadas)
11. [Desactivar NTLMv1 (muy importante)](#11-desactivar-ntlmv1-muy-importante)
12. [Resumen visual del ataque](#12-resumen-visual-del-ataque)
13. [Resumen de mitigaciones](#13-resumen-de-mitigaciones)
14. [Cómo aplicar las principales medidas en Windows](#14-cómo-aplicar-las-principales-medidas-en-windows)
15. [Resumen rápido de rutas](#15-resumen-rápido-de-rutas)

---

## 1. ¿Qué son LLMNR, NBT-NS y WPAD?

| Protocolo | Descripción                                                                                  |
|-----------|---------------------------------------------------------------------------------------------|
| LLMNR     | Resolución de nombres local si el DNS falla (Windows, multicast).                           |
| NBT-NS    | Resolución NetBIOS antigua (Windows).                                                       |
| WPAD      | Descubrimiento automático de proxy web en red local.                                        |

---

## 2. ¿Por qué existen?

| Motivo             | Explicación                                       |
|--------------------|--------------------------------------------------|
| Resolución alterna | Alternativa a DNS para encontrar recursos.        |
| Descubrimiento     | WPAD permite encontrar un proxy automáticamente.  |

---

## 3. ¿Por qué son vulnerables?

| Motivo              | Detalle                                                  |
|---------------------|----------------------------------------------------------|
| Falta de autenticidad | Cualquiera puede responder a peticiones LLMNR/NBT-NS.  |
| Suplantación        | El atacante puede hacerse pasar por el recurso buscado.  |
| Autenticación automática | Windows intenta autenticarse directamente.           |

---

## 4. ¿Qué obtiene el atacante?

| Escenario         | Resultado                                       |
|-------------------|------------------------------------------------|
| Captura de hash   | El atacante obtiene el hash NTLM de la víctima.|
| Relay de hash     | Puede relayar autenticación a otros servicios. |
| Contraseña débil  | Puede crackear y obtener la contraseña.        |

---

## 5. ¿Por qué sigue funcionando?

| Motivo                             | Explicación                                          |
|------------------------------------|-----------------------------------------------------|
| Protocolos activos por defecto     | LLMNR, NBT-NS y WPAD habilitados en Windows modernos.|
| NTLM sigue siendo común            | Mucho software legacy depende de NTLM.              |
| Falta de concienciación            | Muchos desconocen el riesgo.                        |
| Compatibilidad con sistemas antiguos| NTLMv1 sigue activo por dispositivos legacy.         |

---

## 6. Condiciones para ser vulnerable

| Condición                       | Riesgo que implica                                      |
|---------------------------------|---------------------------------------------------------|
| LLMNR/NBT-NS/WPAD habilitados   | Suplantación y captura de autenticaciones.              |
| NTLMv1 habilitado               | Hashes fáciles de crackear.                             |
| NTLMv2 + contraseñas débiles    | Crackeo posible si la contraseña es débil.              |
| SMB/LDAP/HTTP sin signing       | Permiten relay de autenticación NTLM.                   |
| SMB/LDAP signing deshabilitado  | Relay posible si no se exige firma digital.             |
| Usuarios accediendo a nombres erróneos | Aumenta la superficie de ataque.                     |

---

## 7. Por qué NTLMv1 es especialmente peligroso

- Algoritmo débil, fácil de crackear.
- Herramientas como Hashcat/John lo rompen rápido si la contraseña no es robusta.
- NTLMv2 es mucho más seguro (usa "salting" y desafíos fuertes).

---

## 8. ¿Y si la máquina solo usa NTLMv2?

| Escenario                 | Resultado                                               |
|---------------------------|--------------------------------------------------------|
| Captura de hash NTLMv2    | Difícil de crackear si la contraseña es fuerte.        |
| Relay de autenticación    | Sigue siendo posible si no hay mitigación (signing).   |
| Contraseña fuerte         | Hash inútil para cracking.                             |

---

## 9. Funcionamiento del ataque paso a paso

1. Usuario accede a `\\recurso-que-no-existe`.
2. DNS no resuelve el nombre.
3. Windows pregunta vía LLMNR/NBT-NS/WPAD.
4. El atacante responde como si fuera el recurso.
5. Windows intenta autenticarse (NTLM) automáticamente.
6. El atacante captura el hash o lo relayea.

---

## 10. Mitigaciones recomendadas

| Mitigación                            | ¿Qué previene?                              |
|----------------------------------------|---------------------------------------------|
| Desactivar LLMNR/NBT-NS/WPAD           | Evita la suplantación.                      |
| Desactivar NTLMv1                      | Elimina hashes débiles y cracking trivial.  |
| Forzar solo NTLMv2                     | Dificulta el cracking offline.              |
| Habilitar SMB Signing                  | Bloquea el relay NTLM en SMB.               |
| Habilitar LDAP Signing/Channel Binding | Bloquea relay NTLM en LDAP.                 |
| Contraseñas robustas                   | Dificulta cracking NTLMv2.                  |
| Segmentar/red endurecida               | Limita el alcance del atacante.             |
| Migrar servicios a Kerberos            | Elimina el uso de NTLM.                     |
| Revisar dispositivos legacy            | Evita que requieran NTLMv1.                 |

---

## 11. Desactivar NTLMv1 (muy importante)

### Pasos

1. Abre `gpedit.msc`.
2. Ve a:  
   `Configuración del equipo > Configuración de Windows > Configuración de seguridad > Directivas locales > Opciones de seguridad`
3. Busca: **Seguridad de red: Nivel de autenticación de LAN Manager**
4. Selecciona: **Enviar solo respuesta NTLMv2. Rechazar LM y NTLM**
5. (Opcional) **No almacenar el hash de LAN Manager en el próximo cambio de contraseña** → Habilitado.

**Notas:**  
- Así bloqueas NTLMv1 y LM completamente.
- Si tienes dispositivos legacy, migra o aísla.

---

## 12. Resumen visual del ataque

```
Usuario pide acceso a \\recurso-inexistente
    ↓
DNS no resuelve el nombre
    ↓
Windows pregunta vía LLMNR/NBT-NS/WPAD
    ↓
El atacante responde "¡Soy yo!"
    ↓
La víctima intenta autenticarse (NTLM)
    ↓
El atacante captura/relaya el hash
```

---

## 13. Resumen de mitigaciones

| Medida                           | Impacto principal                        |
|-----------------------------------|------------------------------------------|
| Desactivar LLMNR/NBT-NS/WPAD      | Responder deja de funcionar.             |
| Desactivar NTLMv1                 | Hashes capturados no se crackean fácil.  |
| Solo NTLMv2 + contraseñas fuertes | Hashes capturados no se crackean.        |
| SMB/LDAP Signing                  | Relay sobre SMB/LDAP no es posible.      |
| Segmentación de red               | Difícil que el atacante llegue a víctimas|
| Kerberos everywhere               | NTLM deja de usarse, ataque inservible.  |

---

## 14. Cómo aplicar las principales medidas en Windows

### 🚫 Desactivar LLMNR, NBT-NS y WPAD

- **LLMNR**:  
  - `gpedit.msc` > Red > Cliente DNS > Desactivar la resolución de nombres mediante LLMNR → Habilitado
- **NBT-NS**:  
  - Panel de Control > Centro de redes > Cambiar configuración del adaptador > WINS > Deshabilitar NetBIOS sobre TCP/IP
- **WPAD**:  
  - Opciones de Internet > Conexiones > Configuración de LAN > Desmarcar "Detectar configuración automáticamente"

### 🔒 Forzar solo NTLMv2

- `gpedit.msc` > Opciones de seguridad > Nivel de autenticación LAN Manager → Solo NTLMv2

### 📝 Habilitar SMB/LDAP Signing

- **SMB:**  
  - `gpedit.msc` > Opciones de seguridad > Microsoft network client/server: Firmar digitalmente las comunicaciones (siempre) → Habilitado
- **LDAP:**  
  - `gpedit.msc` > Opciones de seguridad > Requisitos de firma del servidor LDAP → Requerir firma
  - Registro: `LDAPEnforceChannelBinding`=2

### 🔑 Contraseñas robustas

- `gpedit.msc` > Directiva de contraseñas > Longitud mínima, complejidad, vigencia

### 🗝️ Segmentación/red endurecida

- VLANs, firewalls, ACLs, etc.

### 🧢 Migrar servicios a Kerberos

- `gpedit.msc` > Opciones de seguridad > Restringir NTLM

### 🧾 Revisar y actualizar legacy

- Asegura soporte NTLMv2 y firmado SMB. Si no, retíralos.

---

## 15. Resumen rápido de rutas

| Medida                | Ubicación/Herramienta                                   |
|-----------------------|--------------------------------------------------------|
| LLMNR                 | gpedit.msc > Cliente DNS                               |
| NBT-NS                | Adaptador de red > WINS                                |
| WPAD                  | Opciones de Internet > Conexiones                      |
| NTLMv1/NTLMv2         | gpedit.msc > Opciones de seguridad > Autenticación LAN |
| SMB Signing           | gpedit.msc > Opciones de seguridad > network client    |
| LDAP Signing          | gpedit.msc > Opciones de seguridad > LDAP/NTDS         |
| Contraseñas fuertes   | gpedit.msc > Directiva de contraseñas                  |
| Segmentación de red   | Infraestructura de red                                 |
| Kerberos/NTLM         | gpedit.msc > Opciones de seguridad > Restringir NTLM   |
| Legacy                | Auditoría manual                                       |

---

**Recomendación:**  
Combina todas las mitigaciones para defensa en profundidad.  
Desactivar NTLMv1 es una de las prioridades más importantes.
