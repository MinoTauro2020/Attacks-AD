# 🛑 PlumHound - Análisis y Reporting Automatizado de BloodHound

---

## 📝 ¿Qué es PlumHound?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Herramienta de análisis post-explotación que automatiza la generación de reportes detallados basados en datos de BloodHound, facilitando la identificación de rutas de ataque y vectores de escalada de privilegios en Active Directory. |
| **Finalidad** | Transformar datos complejos de BloodHound en reportes ejecutivos y técnicos comprensibles, priorizando vectores de ataque críticos y recomendaciones de hardening específicas. |

---

## 🛠️ ¿Cómo funciona PlumHound?

| Fase             | Acción                                                                                         |
|------------------|------------------------------------------------------------------------------------------------|
| **Recolección**  | Importa datos de BloodHound (.json) o se conecta directamente a la base de datos Neo4j.        |
| **Análisis**     | Ejecuta consultas Cypher predefinidas para identificar vulnerabilidades y rutas de ataque.    |
| **Priorización** | Clasifica hallazgos por criticidad, impacto y facilidad de explotación.                       |
| **Reporting**    | Genera reportes HTML/CSV con gráficos, métricas y recomendaciones de mitigación.              |

---

## 💻 Ejemplo práctico

```bash
# Instalación de PlumHound
git clone https://github.com/DefensiveOrigins/PlumHound.git
cd PlumHound
pip3 install -r requirements.txt

# Ejecución básica con datos de BloodHound
python3 PlumHound.py --neo4j bolt://localhost:7687 -u neo4j -p password123

# Generar reporte específico de Domain Admins
python3 PlumHound.py -x tasks/default.tasks -p DomainAdmins --neo4j bolt://localhost:7687 -u neo4j -p password123

# Análisis de rutas de ataque más cortas
python3 PlumHound.py -q "ShortestPaths" --neo4j bolt://localhost:7687 -u neo4j -p password123
```

```
[+] PlumHound Analysis Complete
[+] Domain Admins Analysis: 15 critical paths identified
[+] High Value Targets: 8 accounts with dangerous privileges
[+] Recommended Actions: 23 hardening measures prioritized
[+] Report saved to: reports/PlumHound_Report_2024-07-15.html
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- PlumHound identifica rutas de escalada de privilegios complejas que pueden pasar desapercibidas en análisis manuales
- Automatiza la priorización de riesgos de AD permitiendo enfocar recursos en vulnerabilidades críticas
- 70% de organizaciones tienen rutas de ataque ocultas identificables solo mediante análisis automatizado
- Costo promedio de escalada de privilegios no detectada: $195,000 USD

**Valor de la detección:**
- Identificación proactiva de rutas de ataque antes que los atacantes
- Priorización basada en datos para hardening de AD
- Reducción del tiempo de análisis de vulnerabilidades de AD de semanas a horas
- Cumplimiento con marcos de gestión de identidades privilegiadas

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.0+ o Splunk Cloud
- BloodHound Enterprise o Community con datos actualizados
- PlumHound v1.5+ con acceso a base de datos Neo4j
- Universal Forwarders en sistemas críticos para correlación
- Python 3.8+ con librerías neo4j y pandas

**Arquitectura de datos:**
```
[BloodHound Data] → [Neo4j Database] → [PlumHound Analysis] → [Reports]
       ↓                  ↓                   ↓                  ↓
[AD Objects Graph] [Cypher Queries]  [Vulnerability Analysis] [Splunk Integration]
       ↓                  ↓                   ↓                  ↓
[Users/Groups/OUs] [Attack Paths]    [Risk Prioritization]   [Alerting Dashboard]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 45 min)

1. **Configurar BloodHound y colección de datos:**
   ```powershell
   # Ejecutar SharpHound para recolección
   .\SharpHound.exe -c All -d domain.local --zipfilename bloodhound_data.zip
   
   # Importar datos a BloodHound
   # Arrastrar ZIP a interfaz de BloodHound o usar:
   bloodhound-python -d domain.local -u user -p password -ns 192.168.1.10 -c all
   ```

2. **Instalar y configurar PlumHound:**
   ```bash
   # Instalar PlumHound
   git clone https://github.com/DefensiveOrigins/PlumHound.git
   cd PlumHound
   pip3 install -r requirements.txt
   
   # Configurar acceso a Neo4j
   echo "NEO4J_URI=bolt://localhost:7687" > .env
   echo "NEO4J_USER=neo4j" >> .env
   echo "NEO4J_PASSWORD=bloodhound" >> .env
   ```

3. **Verificar conexión y datos:**
   ```bash
   # Test de conectividad
   python3 PlumHound.py --neo4j bolt://localhost:7687 -u neo4j -p bloodhound --test-connection
   
   # Verificar datos disponibles
   python3 PlumHound.py -q "MATCH (n) RETURN labels(n), count(n)" --neo4j bolt://localhost:7687 -u neo4j -p bloodhound
   ```

#### Fase 2: Implementación de análisis automatizado (Tiempo estimado: 60 min)

1. **Crear task personalizada para análisis crítico:**
   ```json
   {
     "tasks": [
       {
         "QueryName": "CriticalPathsAnalysis",
         "QueryDescription": "Identify critical attack paths to Domain Admins",
         "Query": "MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name: 'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p",
         "Properties": ["user.name", "user.enabled", "user.lastlogon", "path.length"],
         "Report": "DomainAdminPaths"
       },
       {
         "QueryName": "HighValueTargets",
         "QueryDescription": "Users with dangerous privileges",
         "Query": "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH '-518' RETURN u.name, u.enabled, collect(g.name) as groups",
         "Properties": ["name", "enabled", "groups"],
         "Report": "HighValueUsers"
       }
     ]
   }
   ```

2. **Configurar análisis programado:**
   ```bash
   # Script de análisis diario
   cat > /opt/plumhound/daily_analysis.sh << 'EOF'
   #!/bin/bash
   cd /opt/PlumHound
   python3 PlumHound.py -x tasks/critical_analysis.json --neo4j bolt://localhost:7687 -u neo4j -p bloodhound --HTMLTitle "Daily AD Risk Analysis" --HTMLHeader "Security Assessment Report"
   
   # Enviar resultados a Splunk
   /opt/splunkforwarder/bin/splunk add oneshot /opt/PlumHound/reports/PlumHound_Report_$(date +%Y-%m-%d).csv -index ad_analysis -sourcetype plumhound:analysis
   EOF
   chmod +x /opt/plumhound/daily_analysis.sh
   ```

3. **Integrar con Splunk para detección:**
   ```splunk
   # Buscar nuevas rutas críticas detectadas
   index=ad_analysis sourcetype="plumhound:analysis"
   | search CriticalityLevel="HIGH" OR CriticalityLevel="CRITICAL"
   | stats count by AttackPath, RiskLevel, Recommendation
   | where count > _new_baseline_count
   | eval alert_level=case(
       RiskLevel="CRITICAL", "IMMEDIATE",
       RiskLevel="HIGH", "HIGH",
       1=1, "MEDIUM"
   )
   ```

#### Fase 3: Automatización y alertas (Tiempo estimado: 45 min)

1. **Configurar alertas para nuevos vectores:**
   ```splunk
   # Alerta para nuevas rutas de Domain Admin
   index=ad_analysis sourcetype="plumhound:analysis" 
   | search QueryName="CriticalPathsAnalysis"
   | stats dc(AttackPath) as unique_paths by _time
   | where unique_paths > historical_baseline
   | eval severity="CRITICAL", message="New Domain Admin attack paths detected"
   ```

2. **Dashboard de monitoreo:**
   ```xml
   <dashboard>
     <label>PlumHound AD Risk Dashboard</label>
     <row>
       <panel>
         <title>Critical Attack Paths Trend (30 days)</title>
         <chart>
           <search>
             <query>
               index=ad_analysis sourcetype="plumhound:analysis"
               | timechart span=1d count by RiskLevel
             </query>
           </search>
         </chart>
       </panel>
     </row>
   </dashboard>
   ```

3. **Automatización de respuesta:**
   ```bash
   # Script de respuesta automática
   cat > /opt/plumhound/auto_response.py << 'EOF'
   import requests
   import json
   
   def alert_security_team(critical_paths):
       webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
       message = f"🚨 PlumHound Alert: {len(critical_paths)} new critical attack paths detected"
       
       payload = {
           "text": message,
           "attachments": [
               {
                   "color": "danger",
                   "fields": [
                       {"title": "Paths", "value": "\n".join(critical_paths[:5]), "short": True},
                       {"title": "Action Required", "value": "Review and remediate immediately", "short": True}
                   ]
               }
           ]
       }
       
       requests.post(webhook_url, data=json.dumps(payload))
   EOF
   ```

### ✅ Criterios de éxito

**Métricas de análisis:**
- MTTA (Mean Time to Analysis): < 24 horas para nuevos datos de BloodHound
- Reducción de falsos positivos: > 80% comparado con análisis manual
- Cobertura de análisis: 100% de objetos de AD críticos analizados
- Tiempo de generación de reportes: < 30 minutos para dominios de 50k+ objetos

**Validación funcional:**
- [x] Importación exitosa de datos de BloodHound/SharpHound
- [x] Generación de reportes HTML/CSV con métricas críticas
- [x] Identificación de rutas de Domain Admin en < 5 saltos
- [x] Priorización precisa basada en criticidad y facilidad de explotación

### 📊 ROI y propuesta de valor

**Inversión requerida:**
- Tiempo de implementación: 2.5 horas (analista + admin AD)
- Configuración de BloodHound: 45 minutos
- Formación del equipo: 2 horas
- Costo total estimado: $675 USD

**Retorno esperado:**
- Reducción de tiempo de análisis de AD: 85% (de 40 horas a 6 horas)
- Identificación de rutas de ataque críticas: 95% de cobertura
- Ahorro en auditorías de seguridad: $25,000 USD anuales
- ROI estimado: 3,600% en el primer año

### 🧪 Metodología de testing

#### Pruebas de laboratorio

1. **Configurar entorno de AD de prueba:**
   ```powershell
   # Crear usuarios y grupos de prueba
   New-ADUser -Name "TestUser1" -Path "OU=Users,DC=lab,DC=local" -Enabled $true
   New-ADGroup -Name "TestGroup1" -Path "OU=Groups,DC=lab,DC=local" -GroupScope Global
   Add-ADGroupMember -Identity "TestGroup1" -Members "TestUser1"
   ```

2. **Ejecutar recolección y análisis:**
   ```bash
   # Recolectar datos del lab
   python3 bloodhound.py -d lab.local -u testuser -p Password123 -ns 192.168.1.10 -c all
   
   # Ejecutar análisis con PlumHound
   python3 PlumHound.py --neo4j bolt://localhost:7687 -u neo4j -p password --test-lab
   ```

3. **Verificar detección de rutas de prueba:**
   ```bash
   # Buscar rutas específicas creadas en lab
   python3 PlumHound.py -q "MATCH p=(u:User {name: 'TESTUSER1@LAB.LOCAL'})-[*1..3]->(g:Group) RETURN p" --neo4j bolt://localhost:7687 -u neo4j -p password
   ```

#### Validación de rendimiento

1. **Benchmark de análisis:**
   ```bash
   # Medir tiempo de análisis por tamaño de dominio
   time python3 PlumHound.py -x tasks/benchmark.json --neo4j bolt://localhost:7687 -u neo4j -p password
   
   # Análisis de memoria y CPU
   /usr/bin/time -v python3 PlumHound.py -x tasks/full_analysis.json --neo4j bolt://localhost:7687 -u neo4j -p password
   ```

### 🔄 Mantenimiento y evolución

**Revisión semanal:**
- Actualizar datos de BloodHound con recolección incremental
- Revisar nuevas rutas de ataque detectadas
- Validar efectividad de remediaciones implementadas

**Evolución continua:**
- Desarrollar queries personalizadas para casos específicos de la organización
- Integrar con sistemas SOAR para respuesta automatizada
- Crear métricas de reducción de superficie de ataque

**Optimización de rendimiento:**
```bash
# Script de optimización de Neo4j
cypher-shell -u neo4j -p password "CALL db.indexes()"
cypher-shell -u neo4j -p password "CREATE INDEX ON :User(name)"
cypher-shell -u neo4j -p password "CREATE INDEX ON :Group(objectid)"
```

### 🎓 Formación del equipo SOC

**Conocimientos requeridos:**
- Conceptos fundamentales de Active Directory y Kerberos
- Lectura e interpretación de grafos de BloodHound
- Consultas básicas de Cypher para Neo4j
- Priorización de riesgos basada en superficie de ataque

**Material de formación:**
- **Workshop práctico:** 4 horas con entorno lab completo
- **Casos de estudio:** 5 escenarios reales de escalada documentados
- **Playbook específico:** "Análisis y respuesta a hallazgos de PlumHound"
- **Simulacros mensuales:** Ejercicios de análisis de grafos complejos

**Recursos de referencia:**
- [PlumHound Official Documentation](https://github.com/DefensiveOrigins/PlumHound)
- [BloodHound Community Queries](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
- [Neo4j Cypher Manual](https://neo4j.com/docs/cypher-manual/current/)

### 📚 Referencias y recursos adicionales

- [PlumHound GitHub Repository](https://github.com/DefensiveOrigins/PlumHound)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Neo4j Graph Database](https://neo4j.com/docs/)
- [MITRE ATT&CK - Discovery Techniques](https://attack.mitre.org/tactics/TA0007/)
- [AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                           |
|-------------------------------|------------------------------------------------------|
| **BloodHound Collection**     | Actividad de recolección de datos con SharpHound.    |
| **LDAP Queries**              | Consultas LDAP masivas para enumeración de objetos.  |
| **Neo4j Database Access**     | Accesos a base de datos para análisis de grafos.     |
| **Report Generation**         | Generación de reportes y análisis automatizados.     |

### Query Splunk básica

```splunk
index=windows EventCode=4624 OR EventCode=4768 OR EventCode=4769
| search (Process_Name="*SharpHound*" OR Process_Name="*BloodHound*" OR Process_Name="*PlumHound*")
| stats count by ComputerName, Process_Name, Account_Name, _time
```

---

## 🔎 Queries completas para investigación

### 1. Detección de recolección masiva de datos AD

```splunk
index=windows sourcetype=WinEventLog:Security EventCode=4662
| search Object_Type="*domainDNS*" OR Object_Type="*organizationalUnit*"
| bucket _time span=5m
| stats dc(Object_Name) as unique_objects, count as total_accesses by Account_Name, Computer_Name, _time
| where unique_objects > 100 OR total_accesses > 500
```

### 2. Análisis de consultas LDAP sospechosas

```splunk
index=windows sourcetype="WinEventLog:Directory Service" EventCode=1644
| search Search_Filter="*(objectClass=user)*" OR Search_Filter="*(objectClass=group)*"
| stats count values(Search_Filter) as filters by Source_Address, _time
| where count > 50
```

### 3. Correlación con herramientas de análisis de AD

```splunk
index=windows (EventCode=4688 OR EventCode=4624)
| search (Process_Name="*python*" OR Process_Name="*powershell*") AND (CommandLine="*bloodhound*" OR CommandLine="*plumhound*" OR CommandLine="*sharphound*")
| table _time, ComputerName, Account_Name, Process_Name, CommandLine
```

### 4. Detección de acceso a bases de datos Neo4j

```splunk
index=application sourcetype="neo4j:query" OR sourcetype="neo4j:security"
| search cypher_query="*MATCH*" AND (cypher_query="*User*" OR cypher_query="*Group*" OR cypher_query="*Computer*")
| stats count values(cypher_query) as queries by username, client_address, _time
```

### 5. Monitoreo de generación de reportes automatizados

```splunk
index=application sourcetype="plumhound:log"
| search "Report generated" OR "Analysis complete"
| stats count by report_type, analysis_duration, _time
| where analysis_duration > normal_baseline
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Detección de herramientas de análisis de AD
DeviceProcessEvents
| where ProcessCommandLine has_any ("bloodhound", "sharphound", "plumhound", "neo4j")
| where ProcessCommandLine has_any ("-c All", "-CollectionMethod", "--neo4j")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de recolección masiva de datos AD
DeviceEvents
| where ActionType == "LdapQuery"
| where AdditionalFields.SearchFilter contains "objectClass=user" or AdditionalFields.SearchFilter contains "objectClass=group"
| summarize QueryCount = count(), UniqueFilters = dcount(AdditionalFields.SearchFilter) by DeviceId, AccountName, bin(Timestamp, 5m)
| where QueryCount > 100 or UniqueFilters > 20
| order by QueryCount desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **BloodHound Collection Tools** | Detección de SharpHound, BloodHound-py y herramientas similares | Alta |
| **Mass LDAP Enumeration** | Múltiples consultas LDAP en periodo corto | Media |
| **AD Analysis Tools** | Ejecución de PlumHound y herramientas de análisis | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de herramientas de análisis de AD
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*bloodhound* OR FileName=*sharphound* OR FileName=*plumhound* OR CommandLine=*bloodhound* OR CommandLine=*plumhound*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de recolección de datos AD
event_platform=Win event_simpleName=LdapSearch
| search ObjectClass IN (user, group, computer, organizationalUnit)
| bin _time span=5m
| stats dc(SearchFilter) as unique_searches, count as total_searches by ComputerName, UserName, _time
| where unique_searches > 20 OR total_searches > 100
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar análisis masivo de AD
event_platform=Win event_simpleName=DirectoryServiceAccess
| search AccessMask="ReadProperty" AND ObjectType IN (domainDNS, organizationalUnit, user, group)
| bin _time span=10m
| stats count by ComputerName, UserName, ObjectType, _time
| where count > 200
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de PlumHound y herramientas de análisis

```kql
// Query principal para detectar herramientas de análisis de AD
DeviceProcessEvents
| where ProcessCommandLine has_any ("bloodhound", "sharphound", "plumhound")
| where ProcessCommandLine has_any ("-c", "--collection", "--neo4j", "-x")
| summarize count() by DeviceName, AccountName, ProcessCommandLine, bin(TimeGenerated, 5m)
| where count_ > 1
| order by TimeGenerated desc
```

```kql
// Correlación con actividad de enumeración LDAP
IdentityDirectoryEvents
| where ActionType == "LDAP query"
| where AdditionalFields.SearchFilter contains "objectClass"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine contains "bloodhound" or ProcessCommandLine contains "plumhound"
    | project TimeGenerated, DeviceName, ProcessCommandLine, AccountName
) on $left.DeviceName == $right.DeviceName
| where TimeGenerated > TimeGenerated1 and TimeGenerated - TimeGenerated1 < 1h
| project TimeGenerated, DeviceName, ProcessCommandLine, AdditionalFields, AccountName
```

### Hunting avanzado

```kql
// Detección de acceso masivo a objetos de AD
SecurityEvent
| where EventID == 4662 // Access to AD object
| where ObjectType has_any ("domainDNS", "organizationalUnit", "user", "group")
| summarize ObjectAccess = count(), UniqueObjects = dcount(ObjectName) by Account, Computer, bin(TimeGenerated, 10m)
| where ObjectAccess > 500 or UniqueObjects > 100
| order by ObjectAccess desc
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Limitar permisos de recolección**       | Restringir permisos de lectura LDAP para usuarios no administrativos.                       |
| **Monitorizar consultas LDAP masivas**    | Alertar sobre múltiples consultas LDAP desde una sola fuente en periodo corto.             |
| **Segmentar redes de análisis**           | Aislar herramientas de análisis en redes segregadas con acceso controlado.                 |
| **Auditoría de acceso a objetos AD**      | Habilitar auditoría detallada de acceso a objetos críticos de Active Directory.           |
| **Control de herramientas autorizadas**   | Mantener lista de herramientas de análisis aprobadas y detectar ejecutables no autorizados.|
| **Rotación de credenciales privilegiadas**| Rotar regularmente credenciales con acceso de recolección para limitar ventanas de exposición.|
| **Configurar AD con principio de menor privilegio** | Reducir permisos innecesarios para limitar superficie de ataque identificable. |

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Detectar uso no autorizado de PlumHound:**
   - Identificar proceso y usuario ejecutando herramientas de análisis
   - Aislar el sistema origen para prevenir movimiento lateral
   - Revisar logs de autenticación para identificar cuentas comprometidas

2. **Análisis de impacto:**
   - Determinar qué datos de AD fueron enumerados o extraídos
   - Evaluar si se identificaron rutas de escalada críticas
   - Verificar si los hallazgos pueden haber sido exfiltrados

3. **Medidas de contención:**
   - Cambiar credenciales de cuentas con privilegios elevados identificadas
   - Implementar controles adicionales en rutas de ataque críticas detectadas
   - Revisar y fortalecer permisos de objetos AD vulnerables

4. **Investigación forense:**
   - Analizar reportes generados por PlumHound si están disponibles
   - Correlacionar actividad con otros indicadores de compromiso
   - Documentar vectores de ataque para futuras defensas

5. **Recuperación y lecciones aprendidas:**
   - Implementar mitigaciones basadas en hallazgos de PlumHound
   - Actualizar políticas de detección para herramientas similares
   - Realizar análisis propio autorizado para validar postura de seguridad

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para detección de PlumHound no autorizado
function Respond-UnauthorizedPlumHound {
    param($ProcessId, $UserName, $ComputerName)
    
    # Terminar proceso sospechoso
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Stop-Process -Id $using:ProcessId -Force
    }
    
    # Deshabilitar cuenta comprometida temporalmente
    Disable-ADAccount -Identity $UserName
    
    # Registrar incidente
    Write-EventLog -LogName Security -Source "ADSecurity" -EventId 9001 -Message "Unauthorized PlumHound usage detected: User $UserName on $ComputerName"
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: Unauthorized AD Analysis Tool Detected" -Body "PlumHound usage detected on $ComputerName by $UserName. Account temporarily disabled."
}
```

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **PlumHound v1.5+** | Mejoras en análisis de rutas complejas y optimización de consultas Neo4j.             |
| **BloodHound 4.2+** | Nuevas capacidades de análisis de ADCS y mejoras en detección de rutas de escalada.   |
| **Neo4j 4.4+** | Optimizaciones de rendimiento para grafos grandes y mejoras en seguridad de acceso.   |
| **Python 3.9+** | Compatibilidad mejorada con librerías neo4j y pandas para análisis de datos.         |

### Configuraciones de seguridad recomendadas

```bash
# Configuración segura de Neo4j para PlumHound
echo "dbms.security.auth_enabled=true" >> /etc/neo4j/neo4j.conf
echo "dbms.connector.bolt.listen_address=127.0.0.1:7687" >> /etc/neo4j/neo4j.conf
echo "dbms.logs.security.level=INFO" >> /etc/neo4j/neo4j.conf

# Configurar autenticación fuerte
cypher-shell -u neo4j -p default "CALL dbms.security.changePassword('ComplexPassword123!')"

# Crear usuario dedicado para PlumHound
cypher-shell -u neo4j -p ComplexPassword123! "CALL dbms.security.createUser('plumhound', 'PlumH0und!2024', false)"
cypher-shell -u neo4j -p ComplexPassword123! "CALL dbms.security.addRoleToUser('reader', 'plumhound')"
```

### Actualizaciones críticas de seguridad

- **Neo4j Security Updates**: Parches regulares para prevenir injection attacks
- **BloodHound Community Edition**: Actualizaciones de queries y colectores
- **Python Security Patches**: Actualizaciones de dependencias como requests y neo4j-driver

---

## 📚 Referencias

- [PlumHound Official Repository](https://github.com/DefensiveOrigins/PlumHound)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/en/latest/)
- [Neo4j Cypher Query Language](https://neo4j.com/docs/cypher-manual/current/)
- [AD Security Analysis with BloodHound](https://zer1t0.gitlab.io/posts/attacking_ad/)