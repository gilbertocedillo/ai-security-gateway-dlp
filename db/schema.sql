-- AI Security Gateway - Incident Log Schema
-- Postgres / Supabase. Apply: psql "$DATABASE_URL" -f db/schema.sql
-- PRIVACY RULE: only the DLP-REDACTED prompt is ever stored. Raw prompts with
-- live secrets must never be persisted (that would turn the log into a secret store).

create table if not exists incidents (
    id              bigint generated always as identity primary key,
    created_at      timestamptz not null default now(),
    source          text not null default 'n8n',        -- n8n | api | fastapi
    session_id      text,
    category        text not null default 'none'
                    check (category in ('none','direct_injection','jailbreak',
                                        'prompt_extraction','data_exfiltration','dlp')),
    injection_score integer not null default 0 check (injection_score between 0 and 100),
    dlp_findings    jsonb not null default '[]'::jsonb, -- [{type, severity, count, masked_preview}]
    dlp_critical    boolean not null default false,
    redacted_prompt text not null,                      -- REDACTED ONLY, truncated by the gateway
    blocked         boolean not null default false,
    block_reason    text,
    model           text,                               -- final LLM model name, if forwarded
    latency_ms      integer
);

create index if not exists idx_incidents_created_at on incidents (created_at desc);
create index if not exists idx_incidents_blocked on incidents (blocked, created_at desc);
create index if not exists idx_incidents_category on incidents (category);

-- Example: last 24h blocked attacks by category
-- select category, count(*) from incidents
--  where blocked and created_at > now() - interval '24 hours'
--  group by category order by count(*) desc;

-- Retention suggestion: incidents are security telemetry, keep 90 days, then archive/delete:
-- delete from incidents where created_at < now() - interval '90 days';
