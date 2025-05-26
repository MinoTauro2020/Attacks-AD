## ❌ Bloquear totalmente el acceso de "ANONYMOUS LOGON" y "Guest" 

Para bloquear toda la autenticación y el acceso de **ANONYMOUS LOGON** y **Guest** en tu máquina (servidor o cliente), aplica las siguientes configuraciones de seguridad:

---

### ⬛ 1. Denegar acceso a este equipo desde la red

🟦 Abre `secpol.msc` (Política de seguridad local)  
🟦 Ve a:  
**Directivas locales** → **Asignación de derechos de usuario**  
🟦 Busca y edita:  
**Denegar acceso a este equipo desde la red**  
    ⬛ Añade: `ANONYMOUS LOGON`, `Invitados`

---

### ⬛ 2. Denegar inicio de sesión localmente

🟦 En la misma sección (**Asignación de derechos de usuario**):  
🟦 Busca y edita:  
**Denegar inicio de sesión localmente**  
    ⬛ Añade: `ANONYMOUS LOGON`, `Invitados`

---

### ⬛ 3. Restringir el acceso anónimo a recursos compartidos y canales nombrados

🟦 Ve a:  
**Directivas locales** → **Opciones de seguridad**  
🟦 Activa las siguientes opciones:  
- ⬛ **Acceso de red: no permitir la enumeración anónima de cuentas SAM**  
    Establecer en: **Habilitado**
- ⬛ **Acceso de red: no permitir la enumeración anónima de cuentas y recursos SAM**  
    Establecer en: **Habilitado**
- ⬛ **Acceso de red: restringir el acceso anónimo a los canales nombrados y recursos compartidos**  
    Establecer en: **Habilitado**

---

### ⬛ 4. Restringir el acceso anónimo a LDAP (solo en controladores de dominio)

🟦 Abre el editor del registro (`regedit`)  
🟦 Ve a:  
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
```
🟦 Crea o edita el valor DWORD:  
```
LDAPServerIntegrity = 2
```
⬛ Esto obliga a que todas las operaciones LDAP requieran autenticación, bloqueando completamente el acceso anónimo por LDAP.

---

### ⬛ 5. Deshabilitar el acceso de invitado en red (SMB)

🟦 En **Opciones de seguridad**:  
- ⬛ **Acceso de red: modelo de seguridad y uso compartido para cuentas locales**  
    Selecciona: **Solo invitado: los usuarios locales se autentican como Invitado**

---

### ⬛ 6. Reinicia el equipo para que todos los cambios tengan efecto.

---

## 💡 Consejos y notas

- ⬛ No puedes eliminar ni deshabilitar la cuenta **ANONYMOUS LOGON** como si fuera un usuario normal, pero con estas configuraciones todo intento de autenticación será denegado.
- ⬛ Los nombres de cuenta suelen ser insensibles a mayúsculas/minúsculas.
- ⬛ En inglés:  
  - "Asignación de derechos de usuario" = "User Rights Assignment"
  - "Invitados" = "Guests"

---

## 🔒 Resumen de seguridad aplicada

- ⬛ Deniega todo acceso remoto y local de Anonymous y Guest.
- ⬛ Bloquea la enumeración y acceso anónimo por SMB, NetBIOS y LDAP.
- ⬛ Impide cualquier autenticación anónima en la máquina.
