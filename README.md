
<img src="https://github.com/mousastech/security_audit/blob/66f2afa0925c5d08cf4a2ab3e63db6dedc604097/img/header_security_audit.png" width=100%>
# AT&T Mexico - Security Audit Dashboard

**Table of Contents**

- Dashboard Architecture
  - 4 Dashboard Pages
  - 12 SQL Queries Powering the Dashboard
- Query 1: User Activity Overview
- Query 2: Service Principal Inventory
- Query 3: Data Access Audit
- Query 4: Failed & Unauthorized Access
- Query 5: Permission Changes
- Query 6: Service Principal Creation Events
- Query 7: Bulk Data Operations
- Query 8: Admin Activity Audit
- Query 9: Daily Security Summary (KPIs)
- Query 10: Access Pattern Heatmap
- Query 11: Resource Permission Map (WHO has WHAT)
- Query 12: Security Alert Rules
- Deployment Steps
  - Option A: Notebook Deployment (Recommended)
  - Option B: Direct SQL Execution
  - Option C: Dashboard Import
- Recommended Alert Configuration

**Purpose:** Complete visibility into who has access to what resources, data access audit, Service Principal governance, and security alerting.

**Powered by:** Databricks System Tables (system.access.audit, system.information_schema.*)

**Deployment:** Run as a Databricks Notebook or execute SQL queries individually on the AT&T Mexico workspace.

## Dashboard Architecture

### 4 Dashboard Pages

| **Page** | **Purpose** | **CISO Question Answered** |
|---|---|---|
| **Security Overview** | KPIs, daily trends, active users | How active is the platform? What is the failure rate? |
| **Service Principals** | SP inventory, creation events, lifecycle | Who created SPs? Which are active? Which are stale? |
| **Data Access** | Access audit, permission map | WHO has access to WHAT? When did they access it? |
| **Security Alerts** | Anomaly detection, failed access, admin activity | What should I be worried about right now? |

### 12 SQL Queries Powering the Dashboard

| **#** | **Query** | **System Table** | **Key Output** |
|---|---|---|---|
| 1 | User Activity Overview | system.access.audit | All users/SPs with activity stats (30d) |
| 2 | Service Principal Inventory | system.access.audit | Full SP inventory with last activity (90d) |
| 3 | Data Access Audit | system.access.audit | Who accessed which tables/catalogs and when |
| 4 | Failed/Unauthorized Access | system.access.audit | All failed access attempts with error details |
| 5 | Permission Changes | system.access.audit | All grant/revoke/transfer events (90d) |
| 6 | SP Creation Events | system.access.audit | When SPs were created/deleted and by whom |
| 7 | Bulk Data Operations | system.access.audit | Large data exports/credential generation |
| 8 | Admin Activity Audit | system.access.audit | All admin-level operations |
| 9 | Daily Security Summary | system.access.audit | KPI metrics for dashboard header |
| 10 | Access Heatmap | system.access.audit | Activity by hour/day for anomaly detection |
| 11 | Resource Permission Map | system.information_schema.* | Current WHO-has-access-to-WHAT |
| 12 | Security Alerts | system.access.audit | Real-time alert conditions (6 rules) |

## Query 1: User Activity Overview

**Purpose:** Complete inventory of all identities (human users + service principals) active on the platform.

```sql
SELECT
  user_identity.email AS user_email,
  CASE
    WHEN user_identity.email LIKE '%ServicePrincipal%'
      OR user_identity.email LIKE 'SP-%' THEN 'Service Principal'
    WHEN user_identity.email LIKE '%@%' THEN 'Human User'
    ELSE 'System/Unknown'
  END AS identity_type,
  COUNT(*) AS total_events,
  COUNT(DISTINCT DATE(event_time)) AS active_days,
  MIN(event_time) AS first_seen,
  MAX(event_time) AS last_seen,
  COUNT(DISTINCT action_name) AS distinct_actions,
  COUNT(DISTINCT source_ip_address) AS distinct_ips
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
  AND user_identity.email IS NOT NULL
GROUP BY user_identity.email
ORDER BY total_events DESC
```

## Query 2: Service Principal Inventory

**Purpose:** Full inventory of all Service Principals with activity patterns over 90 days.

```sql
SELECT
  user_identity.email AS service_principal,
  COUNT(*) AS total_actions,
  COUNT(DISTINCT action_name) AS distinct_action_types,
  COUNT(DISTINCT DATE(event_time)) AS active_days_last_90d,
  MIN(event_time) AS first_activity,
  MAX(event_time) AS last_activity,
  COUNT(DISTINCT source_ip_address) AS source_ips,
  COUNT(DISTINCT workspace_id) AS workspaces_accessed
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
  AND (
    user_identity.email LIKE '%ServicePrincipal%'
    OR user_identity.email LIKE 'SP-%'
    OR user_identity.email NOT LIKE '%@%'
  )
  AND user_identity.email IS NOT NULL
GROUP BY user_identity.email
ORDER BY last_activity DESC
```

## Query 3: Data Access Audit

**Purpose:** Detailed log of who accessed which data resources and when.

```sql
SELECT
  DATE(event_time) AS access_date,
  user_identity.email AS user_email,
  action_name,
  request_params.full_name_arg AS resource_accessed,
  request_params.catalog_name AS catalog,
  request_params.schema_name AS schema_name,
  response.status_code AS status,
  CASE
    WHEN response.status_code = 200 THEN 'SUCCESS'
    WHEN response.status_code = 403 THEN 'UNAUTHORIZED'
    WHEN response.status_code = 404 THEN 'NOT FOUND'
    ELSE 'FAILURE'
  END AS access_result,
  source_ip_address,
  workspace_id
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
  AND action_name IN (
    'getTable', 'listTables', 'getSchema', 'listSchemas',
    'getCatalog', 'listCatalogs', 'getVolume', 'listVolumes',
    'generateTemporaryTableCredential',
    'generateTemporaryVolumeCredential',
    'getFunction', 'listFunctions', 'getModel', 'listModels'
  )
ORDER BY event_time DESC
```

## Query 4: Failed & Unauthorized Access

**Purpose:** Detect unauthorized access patterns and potential security threats.

```sql
SELECT
  DATE(event_time) AS attempt_date,
  HOUR(event_time) AS attempt_hour,
  user_identity.email AS user_email,
  action_name,
  request_params.full_name_arg AS resource_attempted,
  response.status_code AS status_code,
  response.error_message AS error_message,
  source_ip_address,
  workspace_id,
  COUNT(*) OVER (
    PARTITION BY user_identity.email, DATE(event_time)
  ) AS daily_failures_by_user
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
  AND response.status_code NOT IN (200, 201)
  AND user_identity.email IS NOT NULL
ORDER BY event_time DESC
```

## Query 5: Permission Changes

**Purpose:** Track all permission modifications - who granted/revoked what to whom.

```sql
SELECT
  event_time,
  user_identity.email AS granted_by,
  action_name,
  request_params.securable_type AS resource_type,
  request_params.securable_full_name AS resource_name,
  request_params.principal AS granted_to,
  request_params.privilege AS privilege_granted,
  response.status_code AS status,
  workspace_id
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
  AND action_name IN (
    'updatePermissions', 'updateSharePermissions',
    'grantPermission', 'revokePermission',
    'transferOwnership', 'updateOwner',
    'createGrant', 'deleteGrant'
  )
ORDER BY event_time DESC
```

## Query 6: Service Principal Creation Events

**Purpose:** Track when new SPs are created/deleted and by whom. CRITICAL for CISO.

```sql
SELECT
  event_time,
  user_identity.email AS created_by,
  action_name,
  request_params.display_name AS sp_display_name,
  request_params.application_id AS sp_application_id,
  response.status_code AS status,
  source_ip_address,
  workspace_id
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
  AND action_name IN (
    'createServicePrincipal', 'deleteServicePrincipal',
    'updateServicePrincipal', 'patchServicePrincipal',
    'createServicePrincipalSecret', 'deleteServicePrincipalSecret'
  )
ORDER BY event_time DESC
```

## Query 7: Bulk Data Operations

**Purpose:** Detect large-scale data access that could indicate exfiltration risk.

```sql
SELECT
  DATE(event_time) AS operation_date,
  user_identity.email AS user_email,
  action_name,
  request_params.full_name_arg AS resource_name,
  source_ip_address,
  workspace_id,
  COUNT(*) AS operation_count
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
  AND action_name IN (
    'generateTemporaryTableCredential',
    'generateTemporaryVolumeCredential',
    'downloadNotebookResults',
    'downloadQueryResult',
    'deltaSharingQueryTable',
    'exportNotebook'
  )
GROUP BY
  DATE(event_time), user_identity.email, action_name,
  request_params.full_name_arg, source_ip_address, workspace_id
HAVING COUNT(*) > 10
ORDER BY operation_count DESC
```

## Query 8: Admin Activity Audit

**Purpose:** Track all admin-level operations for accountability.

```sql
SELECT
  event_time,
  user_identity.email AS admin_user,
  action_name,
  service_name,
  response.status_code AS status,
  source_ip_address,
  workspace_id
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
  AND action_name IN (
    'addAdmin', 'removeAdmin',
    'createUser', 'deleteUser', 'updateUser',
    'addGroupMember', 'removeGroupMember',
    'createGroup', 'deleteGroup',
    'createCluster', 'deleteCluster',
    'createPolicy', 'deletePolicy',
    'createSecretScope', 'deleteSecretScope',
    'putSecret', 'deleteSecret',
    'createToken', 'revokeToken'
  )
ORDER BY event_time DESC
```

## Query 9: Daily Security Summary (KPIs)

**Purpose:** Top-level metrics powering the dashboard KPI header.

```sql
SELECT
  DATE(event_time) AS report_date,
  COUNT(DISTINCT user_identity.email) AS total_active_identities,
  COUNT(DISTINCT CASE
    WHEN user_identity.email LIKE '%@%' THEN user_identity.email
  END) AS active_human_users,
  COUNT(DISTINCT CASE
    WHEN user_identity.email NOT LIKE '%@%'
      AND user_identity.email IS NOT NULL
    THEN user_identity.email
  END) AS active_service_principals,
  COUNT(*) AS total_audit_events,
  COUNT(CASE
    WHEN response.status_code NOT IN (200, 201) THEN 1
  END) AS failed_events,
  ROUND(
    COUNT(CASE WHEN response.status_code NOT IN (200, 201) THEN 1 END)
      * 100.0 / COUNT(*), 2
  ) AS failure_rate_pct,
  COUNT(CASE
    WHEN action_name LIKE '%Permission%'
      OR action_name LIKE '%Grant%' THEN 1
  END) AS permission_changes,
  COUNT(CASE
    WHEN action_name LIKE '%ServicePrincipal%' THEN 1
  END) AS sp_events,
  COUNT(DISTINCT source_ip_address) AS distinct_source_ips
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
GROUP BY DATE(event_time)
ORDER BY report_date DESC
```

## Query 10: Access Pattern Heatmap

**Purpose:** Visualize access patterns by hour/day to detect anomalous behavior.

```sql
SELECT
  DATE(event_time) AS access_date,
  HOUR(event_time) AS hour_of_day,
  CASE DAYOFWEEK(event_time)
    WHEN 1 THEN 'Sunday' WHEN 2 THEN 'Monday'
    WHEN 3 THEN 'Tuesday' WHEN 4 THEN 'Wednesday'
    WHEN 5 THEN 'Thursday' WHEN 6 THEN 'Friday'
    WHEN 7 THEN 'Saturday'
  END AS day_name,
  COUNT(*) AS event_count,
  COUNT(DISTINCT user_identity.email) AS unique_users,
  COUNT(CASE
    WHEN response.status_code NOT IN (200, 201) THEN 1
  END) AS failed_events
FROM system.access.audit
WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
GROUP BY DATE(event_time), DAYOFWEEK(event_time), HOUR(event_time)
ORDER BY access_date DESC, hour_of_day
```

## Query 11: Resource Permission Map (WHO has WHAT)

**Purpose:** Complete map of current permissions across the UC hierarchy. This is THE query that answers the CISO's question.

```sql
SELECT
  grantee AS who_has_access,
  CASE
    WHEN grantee LIKE '%@%' THEN 'User'
    WHEN grantee IN ('account users') THEN 'All Account Users'
    ELSE 'Group/SP'
  END AS identity_type,
  privilege AS permission_level,
  securable_type AS resource_type,
  COALESCE(catalog_name, '') AS catalog,
  securable_name AS resource_name,
  inherited_from,
  CASE
    WHEN inherited_from IS NOT NULL THEN 'Inherited'
    ELSE 'Direct Grant'
  END AS grant_type
FROM system.information_schema.catalog_privileges

UNION ALL

SELECT
  grantee,
  CASE
    WHEN grantee LIKE '%@%' THEN 'User'
    WHEN grantee IN ('account users') THEN 'All Account Users'
    ELSE 'Group/SP'
  END,
  privilege_type, 'SCHEMA',
  table_catalog, table_schema,
  NULL, 'Direct Grant'
FROM system.information_schema.schema_privileges

UNION ALL

SELECT
  grantee,
  CASE
    WHEN grantee LIKE '%@%' THEN 'User'
    WHEN grantee IN ('account users') THEN 'All Account Users'
    ELSE 'Group/SP'
  END,
  privilege_type, 'TABLE',
  table_catalog, table_name,
  NULL, 'Direct Grant'
FROM system.information_schema.table_privileges

ORDER BY who_has_access, resource_type, catalog
```

## Query 12: Security Alert Rules

**Purpose:** Configurable alert conditions for real-time monitoring.

```sql
-- ALERT 1: New SP created
SELECT 'NEW_SP_CREATED' AS alert_type, 'HIGH' AS severity,
  event_time, user_identity.email AS triggered_by,
  CONCAT('New SP: ', COALESCE(request_params.display_name, 'unknown'))
    AS alert_message
FROM system.access.audit
WHERE action_name = 'createServicePrincipal'
  AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())

UNION ALL

-- ALERT 2: Admin role changes
SELECT 'ADMIN_CHANGE', 'HIGH',
  event_time, user_identity.email,
  CONCAT(action_name, ' by ', user_identity.email)
FROM system.access.audit
WHERE action_name IN ('addAdmin', 'removeAdmin')
  AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())

UNION ALL

-- ALERT 3: Permission escalation
SELECT 'PERMISSION_CHANGE', 'HIGH',
  event_time, user_identity.email,
  CONCAT(action_name, ' on ',
    COALESCE(request_params.securable_full_name, 'unknown'))
FROM system.access.audit
WHERE action_name IN (
  'updatePermissions', 'grantPermission', 'transferOwnership'
)
AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())

ORDER BY event_time DESC
```

## Deployment Steps

### Option A: Notebook Deployment (Recommended)

- Import the DEPLOY_INSTRUCTIONS.py notebook into the AT&T Mexico workspace
- Create a schema: `CREATE SCHEMA IF NOT EXISTS security_audit`
- Run all cells to create views
- Build Lakeview dashboard pointing to the views

### Option B: Direct SQL Execution

- Connect to any SQL Warehouse in the AT&T Mexico workspace
- Execute each query above as a SQL query in the SQL Editor
- Save queries and pin them to a Lakeview dashboard

### Option C: Dashboard Import

- Use the Lakeview REST API to import lakeview_dashboard.json
- Configure the warehouse_id for AT&T Mexico's SQL Warehouse
- Publish the dashboard

## Recommended Alert Configuration

| **Alert** | **Condition** | **Notification** | **Frequency** |
|---|---|---|---|
| New SP Created | Any createServicePrincipal event | Email to CISO + Security team | Real-time |
| Brute Force | >20 failed attempts in 1 hour by the same user | Email + Teams | Real-time |
| Admin Change | Any addAdmin/removeAdmin event | Email to CISO | Real-time |
| Permission Escalation | Any grant/transfer of ownership | Email to Security team | Hourly digest |
| Off-Hours Access | Data credential generation outside business hours | Email to Security team | Morning digest |
| Bulk Export | >50 credential generations in 1 hour | Email + Teams | Real-time |
