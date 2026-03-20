# Databricks notebook source
# MAGIC %md
# MAGIC # AT&T Mexico - Security Audit Dashboard
# MAGIC ## Deployment Guide for CISO Session
# MAGIC
# MAGIC **Purpose:** This dashboard provides complete visibility into who has access to what resources,
# MAGIC tracks all data access events, monitors Service Principal lifecycle, and alerts on security anomalies.
# MAGIC
# MAGIC **Powered by:** Databricks System Tables (`system.access.audit`, `system.information_schema.*`)
# MAGIC
# MAGIC **Requirements:**
# MAGIC - Unity Catalog enabled (AT&T Mexico: 88% adopted)
# MAGIC - Account Admin or Metastore Admin privileges to query system tables
# MAGIC - SQL Warehouse for dashboard execution
# MAGIC
# MAGIC ---

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 1: Verify System Table Access

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Verify access to audit logs
# MAGIC SELECT COUNT(*) AS audit_events_last_24h
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP())

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Create Security Dashboard Views
# MAGIC These views power the Lakeview dashboard and can also be queried directly.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 1: Daily Security Summary (KPI Header)
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.daily_security_summary AS
# MAGIC SELECT
# MAGIC   DATE(event_time) AS report_date,
# MAGIC   COUNT(DISTINCT user_identity.email) AS total_active_identities,
# MAGIC   COUNT(DISTINCT CASE
# MAGIC     WHEN user_identity.email LIKE '%@%' THEN user_identity.email
# MAGIC   END) AS active_human_users,
# MAGIC   COUNT(DISTINCT CASE
# MAGIC     WHEN user_identity.email NOT LIKE '%@%' AND user_identity.email IS NOT NULL
# MAGIC     THEN user_identity.email
# MAGIC   END) AS active_service_principals,
# MAGIC   COUNT(*) AS total_audit_events,
# MAGIC   COUNT(CASE WHEN response.status_code NOT IN (200, 201) THEN 1 END) AS failed_events,
# MAGIC   ROUND(
# MAGIC     COUNT(CASE WHEN response.status_code NOT IN (200, 201) THEN 1 END) * 100.0 / COUNT(*), 2
# MAGIC   ) AS failure_rate_pct,
# MAGIC   COUNT(CASE WHEN action_name LIKE '%Permission%' OR action_name LIKE '%Grant%' THEN 1 END) AS permission_changes,
# MAGIC   COUNT(CASE WHEN action_name LIKE '%ServicePrincipal%' THEN 1 END) AS sp_events,
# MAGIC   COUNT(DISTINCT source_ip_address) AS distinct_source_ips,
# MAGIC   COUNT(DISTINCT workspace_id) AS workspaces_active
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
# MAGIC GROUP BY DATE(event_time);

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 2: User Activity Overview
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.user_activity_overview AS
# MAGIC SELECT
# MAGIC   user_identity.email AS user_email,
# MAGIC   CASE
# MAGIC     WHEN user_identity.email LIKE '%ServicePrincipal%' OR user_identity.email LIKE 'SP-%' THEN 'Service Principal'
# MAGIC     WHEN user_identity.email LIKE '%@%' THEN 'Human User'
# MAGIC     ELSE 'System/Unknown'
# MAGIC   END AS identity_type,
# MAGIC   COUNT(*) AS total_events,
# MAGIC   COUNT(DISTINCT DATE(event_time)) AS active_days,
# MAGIC   MIN(event_time) AS first_seen,
# MAGIC   MAX(event_time) AS last_seen,
# MAGIC   COUNT(DISTINCT action_name) AS distinct_actions,
# MAGIC   COUNT(DISTINCT source_ip_address) AS distinct_ips
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
# MAGIC   AND user_identity.email IS NOT NULL
# MAGIC GROUP BY user_identity.email;

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 3: Service Principal Inventory
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.service_principal_inventory AS
# MAGIC SELECT
# MAGIC   user_identity.email AS service_principal,
# MAGIC   COUNT(*) AS total_actions,
# MAGIC   COUNT(DISTINCT action_name) AS distinct_action_types,
# MAGIC   COUNT(DISTINCT DATE(event_time)) AS active_days_last_90d,
# MAGIC   MIN(event_time) AS first_activity,
# MAGIC   MAX(event_time) AS last_activity,
# MAGIC   COUNT(DISTINCT source_ip_address) AS source_ips,
# MAGIC   COUNT(DISTINCT workspace_id) AS workspaces_accessed
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
# MAGIC   AND (
# MAGIC     user_identity.email LIKE '%ServicePrincipal%'
# MAGIC     OR user_identity.email LIKE 'SP-%'
# MAGIC     OR user_identity.email NOT LIKE '%@%'
# MAGIC   )
# MAGIC   AND user_identity.email IS NOT NULL
# MAGIC GROUP BY user_identity.email;

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 4: SP Creation Events (CRITICAL for CISO)
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.sp_creation_events AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   user_identity.email AS created_by,
# MAGIC   action_name,
# MAGIC   request_params.display_name AS sp_display_name,
# MAGIC   request_params.application_id AS sp_application_id,
# MAGIC   response.status_code AS status,
# MAGIC   source_ip_address,
# MAGIC   workspace_id
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
# MAGIC   AND action_name IN (
# MAGIC     'createServicePrincipal', 'deleteServicePrincipal',
# MAGIC     'updateServicePrincipal', 'patchServicePrincipal',
# MAGIC     'createServicePrincipalSecret', 'deleteServicePrincipalSecret'
# MAGIC   );

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 5: Failed/Unauthorized Access
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.failed_unauthorized_access AS
# MAGIC SELECT
# MAGIC   DATE(event_time) AS attempt_date,
# MAGIC   user_identity.email AS user_email,
# MAGIC   action_name,
# MAGIC   request_params.full_name_arg AS resource_attempted,
# MAGIC   response.status_code AS status_code,
# MAGIC   response.error_message AS error_message,
# MAGIC   source_ip_address,
# MAGIC   workspace_id
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
# MAGIC   AND response.status_code NOT IN (200, 201)
# MAGIC   AND user_identity.email IS NOT NULL;

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 6: Permission Changes
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.permission_changes AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   user_identity.email AS changed_by,
# MAGIC   action_name,
# MAGIC   request_params.securable_type AS resource_type,
# MAGIC   request_params.securable_full_name AS resource_name,
# MAGIC   request_params.principal AS granted_to,
# MAGIC   request_params.privilege AS privilege_granted,
# MAGIC   response.status_code AS status,
# MAGIC   workspace_id
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -90, CURRENT_TIMESTAMP())
# MAGIC   AND action_name IN (
# MAGIC     'updatePermissions', 'updateSharePermissions',
# MAGIC     'grantPermission', 'revokePermission',
# MAGIC     'transferOwnership', 'updateOwner',
# MAGIC     'createGrant', 'deleteGrant'
# MAGIC   );

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 7: Security Alerts
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.security_alerts AS
# MAGIC
# MAGIC -- New SP created
# MAGIC SELECT 'NEW_SP_CREATED' AS alert_type, 'HIGH' AS severity,
# MAGIC   event_time, user_identity.email AS triggered_by,
# MAGIC   CONCAT('New SP created: ', COALESCE(request_params.display_name, 'unknown')) AS alert_message
# MAGIC FROM system.access.audit
# MAGIC WHERE action_name = 'createServicePrincipal'
# MAGIC   AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
# MAGIC
# MAGIC UNION ALL
# MAGIC
# MAGIC -- Admin role changes
# MAGIC SELECT 'ADMIN_CHANGE' AS alert_type, 'HIGH' AS severity,
# MAGIC   event_time, user_identity.email AS triggered_by,
# MAGIC   CONCAT(action_name, ' by ', user_identity.email) AS alert_message
# MAGIC FROM system.access.audit
# MAGIC WHERE action_name IN ('addAdmin', 'removeAdmin')
# MAGIC   AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP())
# MAGIC
# MAGIC UNION ALL
# MAGIC
# MAGIC -- Permission escalation
# MAGIC SELECT 'PERMISSION_CHANGE' AS alert_type, 'HIGH' AS severity,
# MAGIC   event_time, user_identity.email AS triggered_by,
# MAGIC   CONCAT(action_name, ' on ', COALESCE(request_params.securable_full_name, 'unknown')) AS alert_message
# MAGIC FROM system.access.audit
# MAGIC WHERE action_name IN ('updatePermissions', 'grantPermission', 'transferOwnership')
# MAGIC   AND event_time >= DATEADD(DAY, -7, CURRENT_TIMESTAMP());

# COMMAND ----------

# MAGIC %sql
# MAGIC -- ============================================================
# MAGIC -- VIEW 8: Admin Activity
# MAGIC -- ============================================================
# MAGIC CREATE OR REPLACE VIEW security_audit.admin_activity AS
# MAGIC SELECT
# MAGIC   event_time,
# MAGIC   user_identity.email AS admin_user,
# MAGIC   action_name,
# MAGIC   service_name,
# MAGIC   response.status_code AS status,
# MAGIC   source_ip_address,
# MAGIC   workspace_id
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
# MAGIC   AND action_name IN (
# MAGIC     'addAdmin', 'removeAdmin',
# MAGIC     'enableIpAccessList', 'updateIpAccessList',
# MAGIC     'updateWorkspaceConf', 'setWorkspaceConf',
# MAGIC     'createUser', 'deleteUser', 'updateUser',
# MAGIC     'addGroupMember', 'removeGroupMember',
# MAGIC     'createGroup', 'deleteGroup',
# MAGIC     'createCluster', 'deleteCluster', 'editCluster',
# MAGIC     'createPolicy', 'deletePolicy', 'editPolicy',
# MAGIC     'createSecretScope', 'deleteSecretScope',
# MAGIC     'putSecret', 'deleteSecret',
# MAGIC     'createToken', 'revokeToken'
# MAGIC   );

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 3: Quick Verification Queries
# MAGIC Run these to confirm the dashboard data is populated.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Quick check: How many identities accessed the platform in the last 30 days?
# MAGIC SELECT
# MAGIC   COUNT(DISTINCT user_identity.email) AS total_identities,
# MAGIC   COUNT(DISTINCT CASE WHEN user_identity.email LIKE '%@%' THEN user_identity.email END) AS humans,
# MAGIC   COUNT(DISTINCT CASE WHEN user_identity.email NOT LIKE '%@%' THEN user_identity.email END) AS service_principals
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Quick check: Top 10 most accessed resources
# MAGIC SELECT
# MAGIC   request_params.full_name_arg AS resource,
# MAGIC   COUNT(*) AS access_count,
# MAGIC   COUNT(DISTINCT user_identity.email) AS unique_accessors
# MAGIC FROM system.access.audit
# MAGIC WHERE event_time >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
# MAGIC   AND request_params.full_name_arg IS NOT NULL
# MAGIC   AND action_name IN ('getTable', 'generateTemporaryTableCredential')
# MAGIC GROUP BY request_params.full_name_arg
# MAGIC ORDER BY access_count DESC
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Quick check: Recent permission changes
# MAGIC SELECT * FROM security_audit.permission_changes
# MAGIC ORDER BY event_time DESC
# MAGIC LIMIT 20

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 4: Create Lakeview Dashboard
# MAGIC
# MAGIC After the views are created, build the AI/BI Lakeview dashboard:
# MAGIC
# MAGIC 1. Go to **SQL > Dashboards > Create Dashboard**
# MAGIC 2. Select **AI/BI Dashboard (Lakeview)**
# MAGIC 3. Add datasets pointing to the `security_audit.*` views
# MAGIC 4. Build pages: Security Overview, Service Principals, Data Access, Security Alerts
# MAGIC
# MAGIC Or import the `lakeview_dashboard.json` file provided in this package.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Dashboard Pages Reference
# MAGIC
# MAGIC | Page | Key Widgets | CISO Question Answered |
# MAGIC |------|-------------|----------------------|
# MAGIC | **Security Overview** | KPI counters, daily event trend, user activity table | How active is the platform? Who are the users? |
# MAGIC | **Service Principals** | SP inventory, SP creation events | Who created which SPs? Are any unused? |
# MAGIC | **Data Access** | Access audit table, permission map | Who has access to what? Who accessed what when? |
# MAGIC | **Security Alerts** | Alert conditions, failed access, admin activity | What anomalies should I be concerned about? |
