-- Operational document-envelope schema used by securefi.platform.store.
-- Tenant and kind are part of every primary key. Application authorization is
-- mandatory; this role must not be shared with analysts or search clients.
CREATE TABLE IF NOT EXISTS records (
  tenant TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('event','alert','case','run','resource','notification','evidence','model','asset','draft','registry')),
  id TEXT NOT NULL,
  payload TEXT NOT NULL CHECK (jsonb_typeof(payload::jsonb) = 'object'),
  PRIMARY KEY(tenant,kind,id)
);
CREATE TABLE IF NOT EXISTS audit (
  tenant TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK(seq>0),
  payload TEXT NOT NULL,
  previous TEXT NOT NULL CHECK(length(previous)=64),
  digest TEXT NOT NULL CHECK(length(digest)=64),
  PRIMARY KEY(tenant,seq)
);
CREATE TABLE IF NOT EXISTS jobs (
  tenant TEXT NOT NULL,
  id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','done','dead')),
  payload TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(tenant,id)
);
CREATE TABLE IF NOT EXISTS tenant_locks (tenant TEXT PRIMARY KEY);
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS records_event_time ON records(tenant, ((payload::jsonb)->>'time')) WHERE kind='event';
CREATE INDEX IF NOT EXISTS records_alert_rule ON records(tenant, ((payload::jsonb)->>'rule_id')) WHERE kind='alert';
CREATE OR REPLACE VIEW security_events AS SELECT tenant,id,payload::jsonb AS event FROM records WHERE kind='event';
CREATE OR REPLACE VIEW security_alerts AS SELECT tenant,id,payload::jsonb AS alert FROM records WHERE kind='alert';
CREATE OR REPLACE VIEW security_cases AS SELECT tenant,id,payload::jsonb AS case_record FROM records WHERE kind='case';
CREATE OR REPLACE VIEW response_runs AS SELECT tenant,id,payload::jsonb AS run FROM records WHERE kind='run';
CREATE OR REPLACE VIEW model_registry AS SELECT tenant,id,payload::jsonb AS model FROM records WHERE kind='model';
CREATE OR REPLACE VIEW compliance_evidence AS SELECT tenant,id,payload::jsonb AS evidence FROM records WHERE kind='evidence';
-- Logical references (alert.evidence_ids, case.alert_id, run.case_id) are checked
-- by the application within tenant-scoped transactions. They are not SQL FKs.
-- Use a dedicated non-superuser deployment role and prevent direct table access.
