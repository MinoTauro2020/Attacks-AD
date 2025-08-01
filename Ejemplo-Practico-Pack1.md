# 🎯 Ejemplo Práctico: Implementación Pack 1 con Cliente Bancario

---

## 📋 Caso de Estudio Real

**Cliente**: Banco regional con 1,000 empleados  
**Escenario**: Acceso limitado - Solo SIEM (Scenario B)  
**Duración**: 3 semanas  
**Pack Seleccionado**: Pack 1 - Fundamentos  

---

## 🔍 Semana 1: Hunting de Reconocimiento

### Técnicas Evaluadas
```splunk
# 1. Enumeración SMB - Detectada ✅
index=windows EventCode=5140 Share_Name!="IPC$" earliest=-30d
| stats dc(Share_Name) as shares, dc(Computer) as systems by Account_Name
| where shares > 10 OR systems > 5
| sort -shares
```

**Resultado**: 12 usuarios con actividad de enumeración excesiva identificados

```splunk  
# 2. Anonymous Logon - No Detectada ❌
index=windows EventCode=4624 Logon_Type=3 Account_Name="ANONYMOUS LOGON" earliest=-30d
```

**Resultado**: Sin eventos encontrados - **Gap Crítico Identificado**

---

## 🎫 Semana 2: Hunting de Ataques Kerberos

### AS-REP Roasting
```splunk
index=windows EventCode=4768 Ticket_Options=0x40810000 earliest=-30d
| stats count by Account_Name, Client_Address
| where count > 5
```

**Resultado**: ❌ **No detectado** - Sin reglas configuradas para opciones de ticket específicas

**Recomendación Inmediata**:
```powershell
# Hardening: Forzar preautenticación en todas las cuentas
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false
```

### Kerberoasting
```splunk
index=windows EventCode=4769 Service_Name!="*$" Ticket_Encryption_Type=0x17 earliest=-30d
| stats count, values(Service_Name) by Account_Name
```

**Resultado**: ✅ **Detectado parcialmente** - Solo 3 de 7 service accounts monitoreados

---

## 🔗 Semana 3: Hunting de Relay Attacks

### SMB Relay Detection
```splunk
index=windows EventCode=4624 Logon_Type=3 Source_Network_Address!="127.0.0.1" earliest=-30d
| join Account_Name [search index=windows EventCode=4625 Logon_Type=3 earliest=-30d]
| stats count by Account_Name, Source_Network_Address, Computer
```

**Resultado**: ⚠️ **Detección limitada** - Solo ataques exitosos, faltan intentos

---

## 📊 Resultados Pack 1

### Matriz de Detección
| TTP | Estado | SIEM Alert | Acción Requerida |
|-----|--------|------------|------------------|
| SMB Enumeration | ✅ Detectado | ✅ Alertas configuradas | Optimizar umbral |
| Anonymous Logon | ❌ Gap Crítico | ❌ Sin reglas | **Hardening urgente** |
| AS-REP Roasting | ❌ No detectado | ❌ Sin alertas | Crear regla + hardening |
| Kerberoasting | ⚠️ Parcial | ⚠️ Alertas limitadas | Extender monitorizacion |
| SMB Relay | ⚠️ Parcial | ⚠️ Incompleto | Mejorar correlación |

### Score de Madurez Pack 1
```
Técnicas Detectadas: 1.5 / 5 = 30%
Nivel: 🔴 CRÍTICO - Hardening inmediato requerido
```

---

## 🛡️ Plan de Hardening Inmediato

### Prioridad 1 (Crítica) - 1 semana
1. **Anonymous Logon**:
   ```powershell
   # Deshabilitar acceso anónimo
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
   ```

2. **AS-REP Roasting**:
   ```powershell
   # Forzar preautenticación
   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADUser -DoesNotRequirePreAuth $false
   ```

### Prioridad 2 (Alta) - 2 semanas  
3. **Kerberoasting**:
   ```powershell
   # Cambiar passwords de service accounts
   Get-ADUser -Filter {ServicePrincipalName -like "*"} | Set-ADAccountPassword -Reset
   ```

4. **SMB Relay**:
   ```powershell
   # Habilitar SMB Signing
   Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
   ```

### Prioridad 3 (Media) - 4 semanas
5. **Detección Mejorada**:
   - Implementar 5 nuevas reglas SIEM
   - Dashboard dedicado para Pack 1 TTPs
   - Alertas automáticas con playbooks

---

## 🔄 Roadmap para Pack 2

### Criterios No Cumplidos
- ❌ Score < 70% requerido
- ❌ Controles básicos no implementados
- ❌ Equipo SOC requiere entrenamiento

### Plan de Progresión
1. **Mes 1-2**: Implementar hardening Pack 1
2. **Mes 3**: Re-evaluar con hunting Pack 1  
3. **Mes 4**: Si score ≥ 70%, iniciar Pack 2
4. **Mes 5-6**: Hunting Pack 2 (técnicas avanzadas)

---

## 💰 Propuesta Comercial

### Inversión Pack 1
- **Hunting y Assessment**: 3 semanas - €15,000
- **Hardening Implementation**: 4 semanas - €20,000
- **Training y Playbooks**: 1 semana - €8,000
- **Total Pack 1**: €43,000

### ROI Esperado
- **Reducción de superficie de ataque**: 60%
- **Mejora en tiempo de detección**: De 45 días → 3 horas
- **Preparación para Pack 2**: Base sólida establecida

### Pack 2 (Futuro)
- **Estimado**: €65,000 (6 semanas)
- **Prerrequisito**: Completar Pack 1 exitosamente
- **Beneficio**: Protección contra APTs y ataques avanzados

---

## 📈 KPIs de Seguimiento

### Métricas Semanales
```
Semana 1: Baseline establecido, 5 gaps identificados
Semana 2: 2 reglas implementadas, 1 hardening aplicado  
Semana 3: Score mejorado a 45%, planificación Pack 2
```

### Dashboard Ejecutivo
- 🔴 **Gaps Críticos**: 2 → 0 (objetivo mes 1)
- 🟡 **Detección Parcial**: 3 → 1 (objetivo mes 2)  
- 🟢 **Completamente Detectado**: 1 → 4 (objetivo mes 2)

---

*Este ejemplo demuestra la aplicación práctica del sistema de paquetización en un entorno real bancario con restricciones de acceso típicas del sector financiero.*