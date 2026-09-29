-- Histórico de scans do SentinelKit (opcional).
create table if not exists scans (
  id          uuid primary key default gen_random_uuid(),
  module      text not null check (module in ('deps','web','secrets','apk')),
  target      text not null,
  score       int  not null,
  grade       text not null,
  total       int  not null,
  report      jsonb not null,
  created_at  timestamptz not null default now()
);

create index if not exists scans_created_idx on scans (created_at desc);
create index if not exists scans_module_idx  on scans (module);

-- Se for expor com a anon key, habilite RLS e crie políticas conforme seu caso.
-- alter table scans enable row level security;
