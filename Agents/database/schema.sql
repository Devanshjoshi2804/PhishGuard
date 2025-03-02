-- Enable RLS (Row Level Security)
alter default privileges in schema public grant all on tables to postgres, anon, authenticated, service_role;

-- Phishing Incidents Table
create table if not exists public.phishing_incidents (
    id uuid default uuid_generate_v4() primary key,
    incident_id text unique not null,
    timestamp timestamptz default now(),
    status text default 'pending',
    risk_level text default 'unknown',
    source text,
    raw_data jsonb,
    metadata jsonb,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- Analysis Results Table
create table if not exists public.analysis_results (
    id uuid default uuid_generate_v4() primary key,
    incident_id text references public.phishing_incidents(incident_id),
    email_analysis jsonb,
    url_analysis jsonb,
    domain_analysis jsonb,
    text_analysis jsonb,
    threat_intelligence_analysis jsonb,
    anomaly_detection_analysis jsonb,
    reinforcement_learning_analysis jsonb,
    auto_response_results jsonb,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- Threat Intelligence Table
create table if not exists public.threat_intelligence (
    id uuid default uuid_generate_v4() primary key,
    indicator text not null,
    indicator_type text not null,
    threat_data jsonb,
    confidence float,
    last_seen timestamptz,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);

-- Agent Logs Table
create table if not exists public.agent_logs (
    id uuid default uuid_generate_v4() primary key,
    agent_id text not null,
    incident_id text references public.phishing_incidents(incident_id),
    activity_type text not null,
    details jsonb,
    status text,
    timestamp timestamptz default now()
);

-- Feedback Data Table
create table if not exists public.feedback_data (
    id uuid default uuid_generate_v4() primary key,
    incident_id text references public.phishing_incidents(incident_id),
    feedback_type text not null,
    is_phishing boolean,
    confidence float,
    features jsonb,
    metadata jsonb,
    created_at timestamptz default now()
);

-- Model States Table
create table if not exists public.model_states (
    id uuid default uuid_generate_v4() primary key,
    model_type text not null,
    model_data bytea not null,
    metrics jsonb,
    version text not null,
    created_at timestamptz default now()
);

-- Feature Importance Table
create table if not exists public.feature_importance (
    id uuid default uuid_generate_v4() primary key,
    model_type text not null,
    feature_name text not null,
    importance_score float not null,
    timestamp timestamptz default now()
);

-- Training Metrics Table
create table if not exists public.training_metrics (
    id uuid default uuid_generate_v4() primary key,
    model_type text not null,
    metrics jsonb not null,
    timestamp timestamptz default now()
);

-- System Health Table
create table if not exists public.system_health (
    id uuid default uuid_generate_v4() primary key,
    component text not null,
    status text not null,
    metrics jsonb,
    timestamp timestamptz default now()
);

-- Create indexes
create index if not exists idx_phishing_incidents_incident_id on public.phishing_incidents(incident_id);
create index if not exists idx_analysis_results_incident_id on public.analysis_results(incident_id);
create index if not exists idx_threat_intelligence_indicator on public.threat_intelligence(indicator);
create index if not exists idx_agent_logs_agent_id on public.agent_logs(agent_id);
create index if not exists idx_feedback_data_incident_id on public.feedback_data(incident_id);
create index if not exists idx_model_states_model_type on public.model_states(model_type);

-- Enable Row Level Security (RLS)
alter table public.phishing_incidents enable row level security;
alter table public.analysis_results enable row level security;
alter table public.threat_intelligence enable row level security;
alter table public.agent_logs enable row level security;
alter table public.feedback_data enable row level security;
alter table public.model_states enable row level security;
alter table public.feature_importance enable row level security;
alter table public.training_metrics enable row level security;
alter table public.system_health enable row level security;

-- Create RLS Policies
create policy "Enable read access for all users" on public.phishing_incidents for select using (true);
create policy "Enable insert access for authenticated users" on public.phishing_incidents for insert with check (true);
create policy "Enable update access for authenticated users" on public.phishing_incidents for update using (true);

-- Repeat similar policies for other tables
create policy "Enable read access for all users" on public.analysis_results for select using (true);
create policy "Enable insert access for authenticated users" on public.analysis_results for insert with check (true);
create policy "Enable update access for authenticated users" on public.analysis_results for update using (true);

-- Add updated_at trigger function
create or replace function public.handle_updated_at()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

-- Add updated_at triggers to tables
create trigger handle_updated_at
    before update on public.phishing_incidents
    for each row
    execute function public.handle_updated_at();

create trigger handle_updated_at
    before update on public.analysis_results
    for each row
    execute function public.handle_updated_at();

create trigger handle_updated_at
    before update on public.threat_intelligence
    for each row
    execute function public.handle_updated_at(); 