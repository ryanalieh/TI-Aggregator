create table if not exists lookups (
  id uuid default gen_random_uuid() primary key,
  input text not null,
  input_type text not null,
  result jsonb not null,
  created_at timestamptz default now()
);

create index if not exists lookups_created_at_idx on lookups(created_at desc);
create index if not exists lookups_input_idx on lookups(input);

alter table lookups disable row level security;
