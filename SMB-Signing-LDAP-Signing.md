## 🔒 Configuración de SMB Signing y LDAP Signing en Windows

Guía para endurecer la seguridad de tus sistemas Windows mediante la **firma digital (signing)** de SMB y LDAP, tanto por directiva de grupo como por registro.

---

### 🟦 1. SMB Signing (Firmado SMB)

#### ¿Qué es?
El **firmado SMB** garantiza la integridad de las comunicaciones SMB (compartición de archivos/red) evitando ataques de tipo "man-in-the-middle".

#### ¿Dónde se configura?

#### 📋 A. Directiva de Grupo (GPO)
1. Abre `gpedit.msc` o crea una GPO si es dominio.
2. Navega a:  
   **Configuración del equipo** → **Configuración de Windows** → **Configuración de seguridad** → **Directivas locales** → **Opciones de seguridad**
3. Configura las siguientes opciones:
   - **Microsoft network client: Firmar digitalmente las comunicaciones (siempre)**
   - **Microsoft network client: Firmar digitalmente las comunicaciones (si el servidor está de acuerdo)**
   - **Microsoft network server: Firmar digitalmente las comunicaciones (siempre)**
   - **Microsoft network server: Firmar digitalmente las comunicaciones (si el cliente está de acuerdo)**
4. **Valores recomendados para máxima seguridad:**
   - "siempre" = **Habilitado** (obliga el firmado)
   - "si ... de acuerdo" = Opcional (solo si la contraparte lo soporta)

#### 📋 B. Registro (Registry)
1. Abre `regedit`.
2. Ve a:  
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
   ```
3. Crea o edita estos valores DWORD:
   - `RequireSecuritySignature` = 1  (obligar firmado SMB)
   - `EnableSecuritySignature` = 1   (permitir firmado SMB)

---

### 🟦 2. LDAP Signing (Firmado LDAP)

#### ¿Qué es?
El **firmado LDAP** protege la integridad de las operaciones LDAP (típicamente usadas por Active Directory), previniendo ataques de manipulación en el tráfico.

#### ¿Dónde se configura?

#### 📋 A. Directiva de Grupo (GPO)
1. Abre `gpedit.msc` o una GPO aplicada a los controladores de dominio.
2. Navega a:  
   **Configuración del equipo** → **Configuración de Windows** → **Configuración de seguridad** → **Directivas locales** → **Opciones de seguridad**
3. Configura la directiva:
   - **Controlador de dominio: requisitos de firma del servidor LDAP**
4. **Valores recomendados:**
   - **Requerir firma** — máxima seguridad
   - **Negociar firma** — menos seguro

#### 📋 B. Registro (Registry)
1. Abre `regedit`.
2. Ve a:  
   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
   ```
3. Crea o edita el valor DWORD:
   - `ldapserverintegrity`
     - 2 = Requerir firma (máxima seguridad)
     - 1 = Negociar firma
     - 0 = No requerir

---

## 📝 Resumen Rápido

| Servicio     | Directiva de Grupo                                                    | Registro                                                                                 | Valor recomendado         |
|--------------|-----------------------------------------------------------------------|------------------------------------------------------------------------------------------|--------------------------|
| **SMB**      | Opciones de seguridad > Firmado digital cliente/servidor              | `LanmanServer\Parameters\RequireSecuritySignature = 1`                                   | Siempre habilitado       |
| **LDAP**     | Opciones de seguridad > Requisitos de firma del servidor LDAP         | `NTDS\Parameters\ldapserverintegrity = 2`                                                | Requerir firma           |

---

## 💡 Notas y buenas prácticas

- Aplica estos cambios en **todos los equipos** donde desees máxima seguridad, especialmente en **servidores y controladores de dominio**.
- Tras modificar directivas, ejecuta en cmd:  
  ```
  gpupdate /force
  ```
  para aplicar los cambios.
- Algunos sistemas antiguos o aplicaciones pueden no soportar el firmado obligatorio; valida la compatibilidad antes de desplegar en producción.
- Un reinicio puede ser necesario para cambios en el registro.

---

**¡Con estas configuraciones refuerzas la seguridad de las comunicaciones SMB y LDAP en tu entorno Windows!**

¿Es suficiente para estar 100% protegido?
No completamente.

Relay sobre otros protocolos: Solo SMB y LDAP quedan protegidos. Otros servicios (HTTP, RDP, etc.) pueden seguir siendo vulnerables si no exigen autenticación segura.
Relay entre protocolos distintos: Por ejemplo, de SMB a HTTP, de HTTP a LDAP, etc.
Vulnerabilidades de configuración: Si algún servidor no está configurado para requerir firmado, podría ser vulnerable.
