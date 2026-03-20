# 🛡️ Wazuh + Microsoft Entra ID & Active Directory — Guía Completa de Integración

> **Autor:** Oznet  
> **Fecha:** 2026-03-20  
> **Versión:** 1.0  
> **Objetivo:** Documentar la integración de Wazuh con Microsoft Entra ID (Azure AD) y Active Directory on-premises, incluyendo configuración, reglas nativas y reglas custom.

---

## 📑 Índice

1. [Arquitectura General](#1--arquitectura-general)
2. [Integración con Microsoft Entra ID (Azure AD)](#2--integración-con-microsoft-entra-id-azure-ad)
3. [Integración con Active Directory On-Premises](#3--integración-con-active-directory-on-premises)
4. [Reglas Nativas de Wazuh para AD](#4--reglas-nativas-de-wazuh-para-ad)
5. [Reglas Custom — Active Directory On-Premises](#5--reglas-custom--active-directory-on-premises)
6. [Reglas Custom — Microsoft Entra ID (Azure AD)](#6--reglas-custom--microsoft-entra-id-azure-ad)
7. [CDB List para países permitidos](#7--cdb-list-para-países-permitidos)
8. [Decoder custom para Azure (log files)](#8--decoder-custom-para-azure-log-files)
9. [Tabla de Event IDs clave de Active Directory](#9--tabla-de-event-ids-clave-de-active-directory)
10. [Validación y reinicio](#10--validación-y-reinicio)
11. [Referencias](#11--referencias)

---

## 1. 🏗️ Arquitectura General

Hay **dos flujos distintos** de recolección:

| Fuente | Método de recolección | Tipo de logs |
|---|---|---|
| **Entra ID (Azure AD)** | Módulo `azure-logs` de Wazuh (API Graph / Log Analytics) | Sign-in logs, Audit logs |
| **Active Directory on-prem** | Agente Wazuh en Domain Controllers (Event Channel) | Windows Security Event Log, Directory Service |

```
┌──────────────────┐         ┌──────────────────┐
│  Microsoft       │  API    │                  │
│  Entra ID        │────────▶│  Wazuh Manager   │
│  (Azure AD)      │  Graph  │  (azure-logs)    │
└──────────────────┘         │                  │
                             │   ┌──────────┐   │
┌──────────────────┐  Agent  │   │ Analysis │   │
│  Domain          │────────▶│   │ Engine   │   │
│  Controllers     │  Event  │   └──────────┘   │
│  (AD on-prem)    │ Channel │                  │
└──────────────────┘         └──────────────────┘
```

---

## 2. 🔵 Integración con Microsoft Entra ID (Azure AD)

### 2.1 Prerequisitos en Azure

1. Crear un **App Registration** (Service Principal) en Entra ID
2. Otorgar permisos API:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `SignIn.Read.All`
3. Generar un **Client Secret**
4. Anotar: **Tenant ID**, **Client ID**, **Client Secret**

### 2.2 Configuración en `ossec.conf` (Wazuh Manager)

```xml
<ossec_config>
  <wodle name="azure-logs">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>

    <!-- Logs de Sign-in de Entra ID -->
    <log_analytics>
      <auth_path>/var/ossec/wodles/azure/credentials</auth_path>
      <tenantdomain>YOUR_TENANT_ID</tenantdomain>
      <request>
        <tag>azure-ad-sign-in</tag>
        <query>SigninLogs | where TimeGenerated > ago(5m)</query>
        <workspace>YOUR_WORKSPACE_ID</workspace>
        <time_offset>5m</time_offset>
      </request>
    </log_analytics>

    <!-- Logs de Auditoría de Entra ID -->
    <log_analytics>
      <auth_path>/var/ossec/wodles/azure/credentials</auth_path>
      <tenantdomain>YOUR_TENANT_ID</tenantdomain>
      <request>
        <tag>azure-ad-audit</tag>
        <query>AuditLogs | where TimeGenerated > ago(5m)</query>
        <workspace>YOUR_WORKSPACE_ID</workspace>
        <time_offset>5m</time_offset>
      </request>
    </log_analytics>

    <!-- Método alternativo: Graph API directo -->
    <graph>
      <auth_path>/var/ossec/wodles/azure/credentials</auth_path>
      <tenantdomain>YOUR_TENANT_ID</tenantdomain>
      <request>
        <tag>azure-ad-graph</tag>
        <query>auditLogs/signIns</query>
        <time_offset>5m</time_offset>
      </request>
    </graph>

  </wodle>
</ossec_config>
```

### 2.3 Archivo de credenciales

**Ruta:** `/var/ossec/wodles/azure/credentials`

```ini
application_id = YOUR_CLIENT_ID
application_key = YOUR_CLIENT_SECRET
```

> ⚠️ Proteger este archivo: `chmod 640` y owner `root:wazuh`

---

## 3. 🟢 Integración con Active Directory On-Premises

### 3.1 Prerequisitos

- **Agente Wazuh** instalado en cada **Domain Controller**
- **Audit Policies** habilitadas vía GPO:

| Política | Configuración |
|---|---|
| Audit Account Management | ✅ Success, ✅ Failure |
| Audit Logon Events | ✅ Success, ✅ Failure |
| Audit Directory Service Access | ✅ Success, ✅ Failure |
| Audit Policy Change | ✅ Success, ✅ Failure |
| Audit Privilege Use | ✅ Success, ✅ Failure |

### 3.2 Configuración del agente Wazuh en el DC

**Ruta:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<ossec_config>
  <!-- Log de Seguridad (principal para AD) -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>

  <!-- Log de Directory Service -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Directory Service</location>
  </localfile>

  <!-- Log de DNS Server (opcional, útil para AD-integrated DNS) -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>DNS Server</location>
  </localfile>

  <!-- Sysmon (altamente recomendado para detección avanzada) -->
  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>
</ossec_config>
```

---

## 4. 📋 Reglas Nativas de Wazuh para AD

Wazuh ya trae reglas built-in en los siguientes archivos:

- `/var/ossec/ruleset/rules/0575-win-base_rules.xml`
- `/var/ossec/ruleset/rules/0580-win-security_rules.xml`
- `/var/ossec/ruleset/rules/0585-win-application_rules.xml`

### Reglas nativas que detectan eventos AD:

| Rule ID | Event ID | Descripción | Level |
|---------|----------|-------------|-------|
| 18001 | 4720 | User account was created | 10 |
| 18005 | 4728 | Member added to security-enabled global group | 7 |
| 18007 | 4732 | Member added to security-enabled local group | 7 |
| 18011 | 4739 | Domain Policy was changed | 7 |
| 60106 | 4624 | Successful logon | 3 |
| 60107 | 4625 | Failed logon attempt | 5 |
| 60108 | 4634 | Logoff | 3 |
| 60112 | 4648 | Logon using explicit credentials | 6 |
| 60116 | 4672 | Special privileges assigned to new logon | 6 |

---

## 5. 🔧 Reglas Custom — Active Directory On-Premises

**Archivo:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<!-- ============================================= -->
<!--  CUSTOM RULES: ACTIVE DIRECTORY ON-PREMISES   -->
<!-- ============================================= -->

<group name="custom,windows,active_directory,">

  <!-- ===== GESTIÓN DE CUENTAS ===== -->

  <!-- Cuenta de usuario creada -->
  <rule id="100100" level="10">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4720$</field>
    <description>AD: User account was CREATED - $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1136.002</id>
    </mitre>
    <group>account_created,active_directory,pci_dss_10.2.5,</group>
  </rule>

  <!-- Cuenta de usuario eliminada -->
  <rule id="100101" level="10">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4726$</field>
    <description>AD: User account was DELETED - $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1531</id>
    </mitre>
    <group>account_deleted,active_directory,</group>
  </rule>

  <!-- Cuenta de usuario habilitada -->
  <rule id="100102" level="6">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4722$</field>
    <description>AD: User account was ENABLED - $(win.eventdata.targetUserName)</description>
    <group>account_changed,active_directory,</group>
  </rule>

  <!-- Cuenta de usuario deshabilitada -->
  <rule id="100103" level="6">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4725$</field>
    <description>AD: User account was DISABLED - $(win.eventdata.targetUserName)</description>
    <group>account_changed,active_directory,</group>
  </rule>

  <!-- Cuenta bloqueada (lockout) -->
  <rule id="100104" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4740$</field>
    <description>AD: User account was LOCKED OUT - $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>account_lockout,active_directory,pci_dss_10.2.4,</group>
  </rule>

  <!-- Password reset por admin -->
  <rule id="100105" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4724$</field>
    <description>AD: Password RESET attempted for $(win.eventdata.targetUserName) by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>password_reset,active_directory,pci_dss_10.2.5,</group>
  </rule>

  <!-- ===== CAMBIOS EN GRUPOS DE SEGURIDAD ===== -->

  <!-- Miembro agregado a grupo de seguridad global -->
  <rule id="100110" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4728$</field>
    <description>AD: Member ADDED to security-enabled GLOBAL group: $(win.eventdata.targetUserName) -> $(win.eventdata.groupName)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>group_changed,active_directory,pci_dss_10.2.5,</group>
  </rule>

  <!-- Miembro removido de grupo de seguridad global -->
  <rule id="100111" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4729$</field>
    <description>AD: Member REMOVED from security-enabled GLOBAL group: $(win.eventdata.targetUserName)</description>
    <group>group_changed,active_directory,</group>
  </rule>

  <!-- Miembro agregado a grupo de seguridad local -->
  <rule id="100112" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4732$</field>
    <description>AD: Member ADDED to security-enabled LOCAL group: $(win.eventdata.memberName) -> $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>group_changed,active_directory,</group>
  </rule>

  <!-- Miembro agregado a grupo universal -->
  <rule id="100113" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4756$</field>
    <description>AD: Member ADDED to security-enabled UNIVERSAL group</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>group_changed,active_directory,</group>
  </rule>

  <!-- ===== ALERTAS CRÍTICAS: DOMAIN ADMINS ===== -->

  <!-- Miembro agregado a Domain Admins / Enterprise Admins -->
  <rule id="100120" level="14">
    <if_sid>100110</if_sid>
    <field name="win.eventdata.targetUserName">Domain Admins|Enterprise Admins|Schema Admins|Administrators</field>
    <description>CRITICAL AD: User added to HIGH-PRIVILEGE group $(win.eventdata.targetUserName)!</description>
    <mitre>
      <id>T1078.002</id>
    </mitre>
    <group>admin_escalation,active_directory,pci_dss_10.2.2,</group>
  </rule>

  <!-- ===== GPO CHANGES ===== -->

  <!-- Objeto de directorio modificado (incluye GPO) -->
  <rule id="100130" level="8">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^5136$</field>
    <description>AD: Directory object was MODIFIED - $(win.eventdata.objectDN)</description>
    <group>directory_change,active_directory,</group>
  </rule>

  <!-- GPO modificada específicamente -->
  <rule id="100131" level="12">
    <if_sid>100130</if_sid>
    <field name="win.eventdata.objectClass">groupPolicyContainer</field>
    <description>AD: Group Policy Object (GPO) was MODIFIED - $(win.eventdata.objectDN)</description>
    <mitre>
      <id>T1484.001</id>
    </mitre>
    <group>gpo_change,active_directory,pci_dss_10.2.7,</group>
  </rule>

  <!-- Objeto de directorio eliminado -->
  <rule id="100132" level="10">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^5141$</field>
    <description>AD: Directory object was DELETED - $(win.eventdata.objectDN)</description>
    <group>directory_change,active_directory,</group>
  </rule>

  <!-- ===== BRUTE FORCE / LOCKOUT ===== -->

  <!-- Múltiples fallos de login (brute force) -->
  <rule id="100140" level="12" frequency="8" timeframe="300">
    <if_matched_sid>60107</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>AD BRUTE FORCE: 8+ failed logons for user $(win.eventdata.targetUserName) in 5 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>brute_force,active_directory,pci_dss_11.4,</group>
  </rule>

  <!-- Password spraying (misma IP, diferentes usuarios) -->
  <rule id="100141" level="12" frequency="5" timeframe="300">
    <if_matched_sid>60107</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <different_field>win.eventdata.targetUserName</different_field>
    <description>AD PASSWORD SPRAY: Multiple failed logons from same IP $(win.eventdata.ipAddress) against different users</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>password_spray,active_directory,</group>
  </rule>

  <!-- ===== KERBEROS ATTACKS ===== -->

  <!-- Kerberoasting: TGS request con RC4 -->
  <rule id="100150" level="12">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>AD: Possible KERBEROASTING - TGS requested with RC4 encryption (0x17)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberoasting,active_directory,</group>
  </rule>

  <!-- Golden Ticket: TGT request con RC4 y parámetros inusuales -->
  <rule id="100151" level="14">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <field name="win.eventdata.status">0x0</field>
    <description>AD: Possible GOLDEN TICKET attack - TGT request with RC4 and unusual parameters</description>
    <mitre>
      <id>T1558.001</id>
    </mitre>
    <group>golden_ticket,active_directory,</group>
  </rule>

  <!-- ===== DOMAIN POLICY CHANGES ===== -->

  <rule id="100160" level="10">
    <if_sid>18107</if_sid>
    <field name="win.system.eventID">^4739$</field>
    <description>AD: DOMAIN POLICY was changed</description>
    <mitre>
      <id>T1484</id>
    </mitre>
    <group>policy_changed,active_directory,pci_dss_10.2.7,</group>
  </rule>

</group>
```

---

## 6. 🔵 Reglas Custom — Microsoft Entra ID (Azure AD)

**Archivo:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<!-- ============================================= -->
<!--  CUSTOM RULES: MICROSOFT ENTRA ID (AZURE AD)  -->
<!-- ============================================= -->

<group name="custom,azure,entraid,">

  <!-- ===== BASE: Eventos de Azure AD ===== -->

  <rule id="100200" level="3">
    <decoded_as>json</decoded_as>
    <field name="azure.tag">azure-ad</field>
    <description>Azure Entra ID: Base event received</description>
    <group>azure,entraid,</group>
  </rule>

  <!-- ===== SIGN-IN EVENTS ===== -->

  <!-- Sign-in exitoso -->
  <rule id="100201" level="3">
    <if_sid>100200</if_sid>
    <field name="azure.category">SignInLogs</field>
    <field name="azure.properties.status.errorCode">^0$</field>
    <description>Entra ID: Successful sign-in for $(azure.properties.userPrincipalName)</description>
    <group>authentication_success,azure,entraid,</group>
  </rule>

  <!-- Sign-in fallido -->
  <rule id="100202" level="6">
    <if_sid>100200</if_sid>
    <field name="azure.category">SignInLogs</field>
    <field name="azure.properties.status.errorCode">\S+</field>
    <description>Entra ID: FAILED sign-in for $(azure.properties.userPrincipalName) - Error: $(azure.properties.status.errorCode)</description>
    <group>authentication_failed,azure,entraid,</group>
  </rule>

  <!-- ===== MFA EVENTS ===== -->

  <!-- MFA requerida y fallida -->
  <rule id="100210" level="8">
    <if_sid>100202</if_sid>
    <field name="azure.properties.authenticationRequirement">multiFactorAuthentication</field>
    <description>Entra ID: MFA authentication FAILED for $(azure.properties.userPrincipalName)</description>
    <mitre>
      <id>T1078.004</id>
    </mitre>
    <group>mfa_failed,azure,entraid,</group>
  </rule>

  <!-- MFA fatigue attack: múltiples rechazos de MFA -->
  <rule id="100211" level="12" frequency="3" timeframe="180">
    <if_matched_sid>100210</if_matched_sid>
    <same_field>azure.properties.userPrincipalName</same_field>
    <description>Entra ID: Possible MFA FATIGUE ATTACK - 3+ MFA failures for $(azure.properties.userPrincipalName) in 3 min</description>
    <mitre>
      <id>T1621</id>
    </mitre>
    <group>mfa_fatigue,brute_force,azure,entraid,</group>
  </rule>

  <!-- ===== BRUTE FORCE EN ENTRA ID ===== -->

  <!-- Múltiples sign-ins fallidos desde misma IP -->
  <rule id="100220" level="12" frequency="10" timeframe="600">
    <if_matched_sid>100202</if_matched_sid>
    <same_field>azure.properties.ipAddress</same_field>
    <description>Entra ID: BRUTE FORCE - 10+ failed sign-ins from IP $(azure.properties.ipAddress) in 10 min</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>brute_force,azure,entraid,pci_dss_11.4,</group>
  </rule>

  <!-- Password spray en Entra ID -->
  <rule id="100221" level="12" frequency="5" timeframe="600">
    <if_matched_sid>100202</if_matched_sid>
    <same_field>azure.properties.ipAddress</same_field>
    <different_field>azure.properties.userPrincipalName</different_field>
    <description>Entra ID: PASSWORD SPRAY from IP $(azure.properties.ipAddress) - multiple users targeted</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>password_spray,azure,entraid,</group>
  </rule>

  <!-- ===== CONDITIONAL ACCESS ===== -->

  <!-- Conditional Access denegó acceso -->
  <rule id="100230" level="8">
    <if_sid>100200</if_sid>
    <field name="azure.properties.conditionalAccessStatus">failure</field>
    <description>Entra ID: Conditional Access DENIED sign-in for $(azure.properties.userPrincipalName)</description>
    <group>conditional_access,policy_denied,azure,entraid,</group>
  </rule>

  <!-- Conditional Access: report-only -->
  <rule id="100231" level="4">
    <if_sid>100200</if_sid>
    <field name="azure.properties.conditionalAccessStatus">reportOnlyFailure</field>
    <description>Entra ID: Conditional Access would have DENIED (report-only) for $(azure.properties.userPrincipalName)</description>
    <group>conditional_access,azure,entraid,</group>
  </rule>

  <!-- ===== AUDIT: CAMBIOS EN DIRECTORIO ===== -->

  <!-- Usuario creado en Entra ID -->
  <rule id="100240" level="8">
    <if_sid>100200</if_sid>
    <field name="azure.category">AuditLogs</field>
    <field name="azure.properties.activityDisplayName">Add user</field>
    <description>Entra ID: New user CREATED - $(azure.properties.targetResources.0.userPrincipalName)</description>
    <mitre>
      <id>T1136.003</id>
    </mitre>
    <group>account_created,azure,entraid,pci_dss_10.2.5,</group>
  </rule>

  <!-- Usuario eliminado -->
  <rule id="100241" level="8">
    <if_sid>100200</if_sid>
    <field name="azure.category">AuditLogs</field>
    <field name="azure.properties.activityDisplayName">Delete user</field>
    <description>Entra ID: User DELETED - $(azure.properties.targetResources.0.userPrincipalName)</description>
    <mitre>
      <id>T1531</id>
    </mitre>
    <group>account_deleted,azure,entraid,</group>
  </rule>

  <!-- Rol de admin asignado -->
  <rule id="100242" level="14">
    <if_sid>100200</if_sid>
    <field name="azure.category">AuditLogs</field>
    <field name="azure.properties.activityDisplayName">Add member to role</field>
    <description>Entra ID CRITICAL: User added to ADMIN ROLE - $(azure.properties.targetResources.0.displayName)</description>
    <mitre>
      <id>T1098.003</id>
    </mitre>
    <group>admin_escalation,azure,entraid,pci_dss_10.2.2,</group>
  </rule>

  <!-- App Registration: nuevo secreto creado -->
  <rule id="100243" level="10">
    <if_sid>100200</if_sid>
    <field name="azure.category">AuditLogs</field>
    <field name="azure.properties.activityDisplayName">Add service principal credentials</field>
    <description>Entra ID: New credentials added to Service Principal (possible persistence)</description>
    <mitre>
      <id>T1098.001</id>
    </mitre>
    <group>persistence,azure,entraid,</group>
  </rule>

  <!-- Consent grant (OAuth permission) -->
  <rule id="100244" level="12">
    <if_sid>100200</if_sid>
    <field name="azure.category">AuditLogs</field>
    <field name="azure.properties.activityDisplayName">Consent to application</field>
    <description>Entra ID: Application CONSENT granted - possible illicit consent grant attack</description>
    <mitre>
      <id>T1550.001</id>
    </mitre>
    <group>consent_grant,azure,entraid,</group>
  </rule>

  <!-- ===== SIGN-IN DESDE UBICACIONES SOSPECHOSAS ===== -->

  <!-- Sign-in exitoso desde país inusual (requiere CDB list) -->
  <rule id="100250" level="10">
    <if_sid>100201</if_sid>
    <list field="azure.properties.location.countryOrRegion" lookup="not_match_key">etc/lists/allowed_countries</list>
    <description>Entra ID: Successful sign-in from UNUSUAL COUNTRY: $(azure.properties.location.countryOrRegion) for $(azure.properties.userPrincipalName)</description>
    <mitre>
      <id>T1078.004</id>
    </mitre>
    <group>suspicious_location,azure,entraid,</group>
  </rule>

  <!-- Legacy authentication detected -->
  <rule id="100260" level="8">
    <if_sid>100200</if_sid>
    <field name="azure.properties.clientAppUsed">Exchange ActiveSync|IMAP4|POP3|SMTP|Other clients</field>
    <description>Entra ID: LEGACY authentication protocol used by $(azure.properties.userPrincipalName) via $(azure.properties.clientAppUsed)</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>legacy_auth,azure,entraid,</group>
  </rule>

</group>
```

---

## 7. 📄 CDB List para países permitidos

**Archivo:** `/var/ossec/etc/lists/allowed_countries`

```
AR:allowed
UY:allowed
CL:allowed
BR:allowed
US:allowed
ES:allowed
```

**Registrar en `ossec.conf`:**

```xml
<ruleset>
  <list>etc/lists/allowed_countries</list>
</ruleset>
```

---

## 8. 📝 Decoder custom para Azure (log files)

Si los logs de Azure llegan por archivo JSON (por ejemplo, vía Event Hub → Logstash → archivo):

**Archivo:** `/var/ossec/etc/decoders/local_decoder.xml`

```xml
<decoder name="azure-entraid">
  <prematch>\"category\":\"SignInLogs\"|\"category\":\"AuditLogs\"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="azure-entraid-fields">
  <parent>azure-entraid</parent>
  <regex offset="after_parent">\"userPrincipalName\":\"(\S+)\"</regex>
  <order>user</order>
</decoder>
```

---

## 9. 📊 Tabla de Event IDs clave de Active Directory

| Event ID | Descripción | Nivel sugerido |
|----------|-------------|----------------|
| **4720** | Cuenta creada | 10 |
| **4722** | Cuenta habilitada | 6 |
| **4724** | Password reset | 8 |
| **4725** | Cuenta deshabilitada | 6 |
| **4726** | Cuenta eliminada | 10 |
| **4728** | Miembro agregado a grupo global | 8 |
| **4729** | Miembro removido de grupo global | 8 |
| **4732** | Miembro agregado a grupo local | 8 |
| **4733** | Miembro removido de grupo local | 8 |
| **4739** | Domain policy cambiada | 10 |
| **4740** | Cuenta bloqueada | 8 |
| **4756** | Miembro agregado a grupo universal | 8 |
| **4768** | TGT requested (Kerberos) | 3/14 |
| **4769** | TGS requested (Kerberoasting) | 3/12 |
| **4771** | Kerberos pre-auth failed | 5 |
| **4776** | NTLM authentication | 3 |
| **5136** | Objeto de directorio modificado | 8 |
| **5141** | Objeto de directorio eliminado | 10 |
| **4624** | Logon exitoso | 3 |
| **4625** | Logon fallido | 5 |
| **4648** | Logon con credenciales explícitas | 6 |
| **4672** | Privilegios especiales asignados | 6 |

---

## 10. ⚡ Validación y reinicio

```bash
# Validar la configuración
/var/ossec/bin/wazuh-logtest

# Verificar que las reglas compilen bien
/var/ossec/bin/wazuh-analysisd -t

# Reiniciar el manager
systemctl restart wazuh-manager
```

---

## 11. 📚 Referencias

| Recurso | URL |
|---|---|
| Wazuh Azure module | https://documentation.wazuh.com/current/cloud-security/azure/index.html |
| Wazuh Windows Event Channel | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html |
| Wazuh Ruleset GitHub | https://github.com/wazuh/wazuh/tree/master/ruleset/rules |
| Microsoft Security Event IDs | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview |
| SOCFortress Wazuh Rules (community) | https://github.com/socfortress/Wazuh-Rules |
| Azure AD Sign-in error codes | https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes |

---

> 📌 **Nota:** Adaptar los campos `azure.properties.*` y `win.eventdata.*` según el formato real de logs de tu entorno. Siempre validar con `wazuh-logtest` antes de poner en producción.