-- ============================================================
-- AGNL — upgrade HEMAT Supabase (jalankan SEKALI di SQL Editor)
-- Aman dijalankan berulang. Transaksi kini 1 baris per transaksi (key 'tx:<id>'),
-- file ini menambah trigger updated_at, index pencarian, dan fungsi statistik admin.
-- ============================================================

-- 1) updated_at otomatis (dipakai untuk mencegah tulisan basi menimpa data baru)
create or replace function public._set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;

drop trigger if exists trg_set_updated_at on public.keyvalue_store;
create trigger trg_set_updated_at before update on public.keyvalue_store
  for each row execute function public._set_updated_at();

-- 2) index pencarian transaksi (hanya untuk baris tx:*)
create index if not exists kv_tx_status  on public.keyvalue_store ((value->>'status'))    where key like 'tx:%';
create index if not exists kv_tx_userid  on public.keyvalue_store ((value->>'userId'))    where key like 'tx:%';
create index if not exists kv_tx_orderid on public.keyvalue_store ((value->>'orderId'))   where key like 'tx:%';
create index if not exists kv_tx_code    on public.keyvalue_store ((value->>'code'))      where key like 'tx:%';
create index if not exists kv_tx_created on public.keyvalue_store ((value->>'createdAt')) where key like 'tx:%';

-- 3) statistik admin dihitung di database (hasilnya beberapa ratus byte, bukan ribuan transaksi)
create or replace function public.tx_stats(p_days int default 8)
returns jsonb language sql stable as $$
  select jsonb_build_object(
    'total',   count(*),
    'pending', count(*) filter (where value->>'status' = 'pending'),
    'done',    count(*) filter (where value->>'status' = 'done'),
    'revenue', coalesce(sum(case when value->>'price' ~ '^-?[0-9.]+$' then (value->>'price')::numeric else 0 end)
                        filter (where value->>'status' = 'done'), 0),
    'daily', coalesce((
      select jsonb_object_agg(d, jsonb_build_object('count', c, 'revenue', r))
      from (
        select left(value->>'createdAt', 10) as d, count(*) as c,
               sum(case when value->>'price' ~ '^-?[0-9.]+$' then (value->>'price')::numeric else 0 end) as r
        from public.keyvalue_store
        where key like 'tx:%' and value->>'status' = 'done'
          and left(value->>'createdAt', 10) >= to_char(now() - make_interval(days => p_days), 'YYYY-MM-DD')
        group by 1
      ) x), '{}'::jsonb)
  )
  from public.keyvalue_store where key like 'tx:%';
$$;

-- fungsi hanya untuk server (service_role); anon/authenticated tidak perlu
revoke all on function public.tx_stats(int) from public, anon, authenticated;
grant execute on function public.tx_stats(int) to service_role;
