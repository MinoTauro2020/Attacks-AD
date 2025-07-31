# 🛑 Enumeración de Active Directory con rpcclient

---

## 📝 ¿Qué es la enumeración con rpcclient?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Uso de la herramienta rpcclient para obtener el listado completo de usuarios y grupos de Active Directory, incluso con cuentas de bajo privilegio. Permite a cualquier atacante mapear el dominio y preparar fases posteriores de ataque. |
| **Requisito** | Acceso a una cuenta válida (no es necesario que sea privilegiada) y conectividad con el controlador de dominio (puertos RPC/SMB abiertos). |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Autenticación**   | El atacante se conecta con una cuenta válida al DC usando rpcclient.                                   |
| **Enumeración**     | Ejecuta los comandos `enumdomusers` y `enumdomgroups` para extraer el listado de usuarios y grupos del dominio. |
| **Reconocimiento**  | Identifica cuentas privilegiadas, cuentas de servicio, naming conventions y posibles objetivos para password spraying o phishing. |
| **Preparación**     | Usa la información obtenida para lanzar ataques dirigidos (spraying, movimiento lateral, explotación de servicios, etc.). |

---

## 💻 Ejemplo práctico ofensivo (comandos reales)

```bash
# Enumerar grupos del dominio
rpcclient -U "usuario" IP_DC -c "enumdomgroups"

# Enumerar usuarios del dominio
rpcclient -U "usuario" IP_DC -c "enumdomusers"
```
> Ejemplo de salida real:
> ```
> group:[Domain Admins] rid:[0x200]
> group:[Enterprise Admins] rid:[0x207]
> ...
> user:[administrator] rid:[0x1f4]
> user:[sql_svc] rid:[0x45e]
> user:[daenerys.targaryen] rid:[0x458]
> ```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                              |
|--------------|-----------------------------------------------------------------------------------------|
| **4624**     | Inicio de sesión de red (tipo 3) con cuentas poco usadas o fuera de horario.            |
| **4776**     | Autenticación de cuenta (NTLM/Kerberos), especialmente desde IPs no habituales.         |
| **5140**     | Acceso a recurso compartido de red (\\IPC$): patrón de acceso masivo o inusual.         |
| **5145**     | Detalle de acceso a carpeta compartida (si hay auditoría de objetos).                   |

### Query Splunk básica para detección de enumeración

```splunk
index=wineventlog (EventCode=5140 OR EventCode=5145 OR EventCode=4624 OR EventCode=4776)
| stats count by host, Account_Name, Source_Network_Address, EventCode, Share_Name, Logon_Type, _time
| where (EventCode=5140 AND Share_Name="\\*\IPC$") OR (EventCode=4624 AND Logon_Type=3)
| sort - _time
```

### Detección de patrones masivos o fuera de lo común

```splunk
index=wineventlog (EventCode=5140)
| stats count by Account_Name, Source_Network_Address, Share_Name, earliest(_time), latest(_time)
| where count > 10 AND Share_Name="\\*\IPC$"
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Restringe acceso a SAM-RPC**           | GPO: “Network access: Restrict anonymous access to Named Pipes and Shares” y “Network access: Restrict anonymous SAM accounts enumeration” en Habilitado. |
| **Limita acceso a \\IPC$**               | Solo para administradores y sistemas de gestión autorizados.                                     |
| **Auditoría avanzada**                   | Activa auditoría detallada de acceso a objetos y monitoriza eventos 5140/5145.                   |
| **Honeytokens de usuario/grupo**         | Crea cuentas y grupos trampa: si aparecen en logs de enumeración, alerta inmediata.              |
| **Microsegmentación**                    | Solo permite tráfico RPC/SAMR desde segmentos seguros y predefinidos.                            |
| **Elimina cuentas innecesarias**         | Revisa y borra cuentas antiguas, de prueba o poco usadas.                                        |
| **Revisión periódica de cuentas de servicio** | Confirma que no tienen privilegios excesivos ni contraseñas débiles.                          |

---

## 🚨 Respuesta ante incidentes

1. **Identifica IP y usuario origen en eventos 5140/5145/4624.**
2. **Verifica legitimidad del acceso: ¿Era un sistema autorizado? ¿Un usuario habitual?**
3. **Aísla la máquina origen si es sospechosa y fuerza el cambio de credenciales usadas.**
4. **Realiza búsqueda retroactiva de actividad similar desde otras IPs o cuentas.**
5. **Despliega reglas de detección en tiempo real para accesos masivos o inusuales a \\IPC$.**

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025221** | Windows 11/10 - Mejoras en protección contra enumeración RPC y limitación de acceso anónimo.|
| **KB5022906** | Windows Server 2022 - Fortalecimiento de controles RPC y auditoría de consultas anónimas.  |
| **KB5022845** | Windows Server 2019 - Correcciones en configuraciones RPC por defecto y acceso restringido.|
| **KB4580390** | Windows Server 2016 - Parches críticos para limitar enumeración vía RPC y protocolos SMB.  |
| **KB4556836** | Zerologon patch - Crítico para prevenir bypass completo de autenticación vía RPC.          |
| **RPC Hardening Updates** | Actualizaciones específicas del subsistema RPC para mejor autenticación.          |

### Configuraciones de registro críticas

```powershell
# Restringir acceso RPC anónimo
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 2

# Configurar autenticación RPC obligatoria
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\ClientProtocols" -Name "AuthnLevel" -Value 6

# Limitar interfaces RPC expuestas
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\SecurityService" -Name "DefaultAuthLevel" -Value 6

# Auditoría de acceso RPC
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas RPC restrictivas
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Network access: Restrict clients allowed to make remote calls to SAM" = Configurar lista restrictiva
# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled

# Configurar firewall para RPC
New-NetFirewallRule -DisplayName "Block RPC Anonymous" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block -RemoteAddress "Any"
```

### Scripts de validación y detección

```powershell
# Verificar configuraciones RPC
$restrictRPC = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
if ($restrictRPC.RestrictAnonymous -eq 2) {
    Write-Host "✓ Acceso RPC anónimo restringido" -ForegroundColor Green
} else {
    Write-Host "✗ RESTRINGIR acceso RPC anónimo" -ForegroundColor Red
}

# Detectar conexiones RPC sospechosas
$rpcConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 135 -and $_.State -eq "Established"}
$rpcConnections | Group-Object RemoteAddress | Where-Object Count -gt 5 |
ForEach-Object {
    Write-Warning "Múltiples conexiones RPC desde: $($_.Name) - $($_.Count) conexiones"
}

# Monitorear procesos rpcclient o similares
Get-Process | Where-Object {$_.ProcessName -match "(rpcclient|net|wmic)"} |
ForEach-Object {
    Write-Warning "Herramienta de enumeración RPC detectada: $($_.ProcessName) PID:$($_.Id)"
}
```

### Actualizaciones críticas de seguridad

- **CVE-2020-1472**: Zerologon - bypass crítico de autenticación vía RPC (KB4556836)
- **CVE-2017-0143**: EternalBlue - afecta también protocolos RPC/SMB (KB4013389)
- **CVE-2019-1040**: LDAP/RPC relay attack bypass (KB4511553)
- **CVE-2021-36942**: Vulnerabilidades RPC que facilitan coerción (KB5005413)

---

## 📚 Referencias

- [rpcclient - Samba suite](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)
- [Abusing Active Directory with rpcclient](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/enumeration#rpcclient)
- [CVE-2017-0143 (SMBv1 RCE)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0143)
- [CVE-2020-1472 (Zerologon)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
