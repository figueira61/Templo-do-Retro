-- ============================================================================
-- Templo do Retro: base de dados multiplayer (Supabase / Postgres)
--
-- Como usar: Supabase > SQL Editor > New query > colar este ficheiro todo > Run.
-- Pode ser executado mais do que uma vez sem estragar nada.
--
-- Segurança: as tabelas ficam fechadas ao público (RLS ligado, sem políticas).
-- Os sites só falam com a base de dados através das funções no fim deste
-- ficheiro. O PIN nunca é guardado em claro, só o seu hash (bcrypt).
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;
create extension if not exists unaccent with schema extensions;

-- ---------------------------------------------------------------------------
-- Tabelas
-- ---------------------------------------------------------------------------

create table if not exists public.players (
  id            bigint generated always as identity primary key,
  username      text        not null,
  -- Nome normalizado (sem acentos, maiúsculas nem separadores). É esta chave
  -- que garante que "Ana", "ana" e "A.na" contam como o mesmo nome.
  username_key  text        not null unique,
  pin_hash      text        not null,
  failed_pins   int         not null default 0,
  locked_until  timestamptz,
  created_at    timestamptz not null default now(),
  constraint players_username_len check (char_length(username) between 2 and 16)
);

create table if not exists public.sessions (
  token_hash text primary key,
  player_id  bigint      not null references public.players (id) on delete cascade,
  created_at timestamptz not null default now(),
  last_seen  timestamptz not null default now()
);
create index if not exists sessions_player_idx on public.sessions (player_id);

create table if not exists public.game_stats (
  player_id   bigint      not null references public.players (id) on delete cascade,
  game        text        not null check (game in ('snake', 'forca', 'pacman', 'dino')),
  best_score  int         not null default 0,  -- snake / pacman / dino: recorde
  games       int         not null default 0,  -- jogos terminados
  wins        int         not null default 0,  -- forca
  losses      int         not null default 0,  -- forca
  streak      int         not null default 0,  -- forca: sequência atual
  best_streak int         not null default 0,  -- forca: melhor sequência
  updated_at  timestamptz not null default now(),
  primary key (player_id, game)
);

-- Bases já existentes: atualiza a lista de jogos permitidos (pode correr várias vezes).
alter table public.game_stats drop constraint if exists game_stats_game_check;
alter table public.game_stats add constraint game_stats_game_check
  check (game in ('snake', 'forca', 'pacman', 'dino'));

-- Tabelas fechadas: ninguém lê nem escreve diretamente a partir do navegador.
alter table public.players    enable row level security;
alter table public.sessions   enable row level security;
alter table public.game_stats enable row level security;
revoke all on table public.players    from anon, authenticated;
revoke all on table public.sessions   from anon, authenticated;
revoke all on table public.game_stats from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Funções internas (não acessíveis a partir do navegador)
-- ---------------------------------------------------------------------------

create or replace function public.retro_key(p text)
returns text
language sql
stable
set search_path = public, extensions
as $$
  select regexp_replace(
           lower(unaccent(regexp_replace(btrim(coalesce(p, '')), '\s+', ' ', 'g'))),
           '[ ._-]+', '', 'g');
$$;

create or replace function public.retro_new_session(p_player bigint)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_token text := encode(gen_random_bytes(24), 'hex');
begin
  insert into public.sessions (token_hash, player_id)
  values (encode(digest(v_token, 'sha256'), 'hex'), p_player);

  -- Limpeza: sessões com mais de 180 dias e, por jogador, só as 10 mais recentes.
  delete from public.sessions where created_at < now() - interval '180 days';
  delete from public.sessions s
   where s.player_id = p_player
     and s.token_hash not in (
       select token_hash from public.sessions
        where player_id = p_player
        order by created_at desc
        limit 10);
  return v_token;
end;
$$;

create or replace function public.retro_player_from_token(p_token text)
returns bigint
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_id bigint;
begin
  if p_token is null or p_token = '' then
    return null;
  end if;
  update public.sessions
     set last_seen = now()
   where token_hash = encode(digest(p_token, 'sha256'), 'hex')
     and created_at > now() - interval '180 days'
  returning player_id into v_id;
  return v_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Funções públicas (chamadas pelos sites)
-- ---------------------------------------------------------------------------

-- Criar conta: nome único + PIN de 4 a 6 dígitos.
create or replace function public.register_player(p_username text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := regexp_replace(btrim(coalesce(p_username, '')), '\s+', ' ', 'g');
  v_norm text := lower(unaccent(regexp_replace(btrim(coalesce(p_username, '')), '\s+', ' ', 'g')));
  v_key  text := public.retro_key(p_username);
  v_id   bigint;
begin
  if char_length(v_name) < 2 or char_length(v_name) > 16
     or v_norm !~ '^[a-z0-9][a-z0-9 ._-]*$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_name');
  end if;
  if p_pin is null or p_pin !~ '^[0-9]{4,6}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_pin');
  end if;
  -- Limite de segurança para o plano gratuito. Aumenta se um dia for preciso.
  if (select count(*) from public.players) >= 5000 then
    return jsonb_build_object('ok', false, 'error', 'full');
  end if;

  begin
    insert into public.players (username, username_key, pin_hash)
    values (v_name, v_key, crypt(p_pin, gen_salt('bf', 8)))
    returning id into v_id;
  exception when unique_violation then
    return jsonb_build_object('ok', false, 'error', 'name_taken');
  end;

  return jsonb_build_object('ok', true, 'username', v_name,
                            'token', public.retro_new_session(v_id));
end;
$$;

-- Entrar com nome + PIN. Depois de 5 PINs errados a conta fica 10 minutos bloqueada.
create or replace function public.login_player(p_username text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_p public.players;
begin
  select * into v_p from public.players
   where username_key = public.retro_key(p_username);

  if not found then
    return jsonb_build_object('ok', false, 'error', 'wrong_credentials');
  end if;

  if v_p.locked_until is not null and v_p.locked_until > now() then
    return jsonb_build_object('ok', false, 'error', 'locked',
             'retry_in', ceil(extract(epoch from (v_p.locked_until - now())))::int);
  end if;

  if v_p.pin_hash = crypt(coalesce(p_pin, ''), v_p.pin_hash) then
    update public.players set failed_pins = 0, locked_until = null where id = v_p.id;
    return jsonb_build_object('ok', true, 'username', v_p.username,
                              'token', public.retro_new_session(v_p.id));
  end if;

  update public.players
     set failed_pins  = case when failed_pins + 1 >= 5 then 0 else failed_pins + 1 end,
         locked_until = case when failed_pins + 1 >= 5
                             then now() + interval '10 minutes'
                             else locked_until end
   where id = v_p.id;
  return jsonb_build_object('ok', false, 'error', 'wrong_credentials');
end;
$$;

-- Verificar se a sessão guardada no telemóvel continua válida.
create or replace function public.check_session(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_id   bigint := public.retro_player_from_token(p_token);
  v_name text;
begin
  if v_id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  select username into v_name from public.players where id = v_id;
  return jsonb_build_object('ok', true, 'username', v_name);
end;
$$;

-- Terminar sessão.
create or replace function public.logout_player(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  delete from public.sessions
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  return jsonb_build_object('ok', true);
end;
$$;

-- Registar o resultado de um jogo.
--   snake / pacman / dino: p_score = pontos da partida (guarda o melhor)
--   forca: p_result = 'win' ou 'loss'
create or replace function public.submit_result(
  p_token text, p_game text, p_score int default null, p_result text default null)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_pid bigint := public.retro_player_from_token(p_token);
  v_s   public.game_stats;
begin
  if v_pid is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  if p_game not in ('snake', 'forca', 'pacman', 'dino') then
    return jsonb_build_object('ok', false, 'error', 'invalid_game');
  end if;
  if p_game in ('snake', 'pacman', 'dino')
     and (p_score is null or p_score < 0
          or p_score > case p_game when 'snake' then 10000
                                   when 'pacman' then 500000
                                   else 100000 end) then
    return jsonb_build_object('ok', false, 'error', 'invalid_score');
  end if;
  if p_game = 'forca' and (p_result is null or p_result not in ('win', 'loss')) then
    return jsonb_build_object('ok', false, 'error', 'invalid_result');
  end if;

  insert into public.game_stats (player_id, game)
  values (v_pid, p_game)
  on conflict (player_id, game) do nothing;

  select * into v_s from public.game_stats
   where player_id = v_pid and game = p_game
   for update;

  -- Travão simples contra envios em rajada (uma partida real demora mais).
  if v_s.games > 0 and v_s.updated_at > now() - interval '2 seconds' then
    return jsonb_build_object('ok', false, 'error', 'too_fast');
  end if;

  if p_game in ('snake', 'pacman', 'dino') then
    update public.game_stats
       set best_score = greatest(best_score, p_score),
           games      = games + 1,
           updated_at = now()
     where player_id = v_pid and game = p_game
     returning * into v_s;
  elsif p_result = 'win' then
    update public.game_stats
       set wins        = wins + 1,
           streak      = streak + 1,
           best_streak = greatest(best_streak, streak + 1),
           games       = games + 1,
           updated_at  = now()
     where player_id = v_pid and game = p_game
     returning * into v_s;
  else
    update public.game_stats
       set losses     = losses + 1,
           streak     = 0,
           games      = games + 1,
           updated_at = now()
     where player_id = v_pid and game = p_game
     returning * into v_s;
  end if;

  return jsonb_build_object('ok', true, 'stats', jsonb_build_object(
    'best_score', v_s.best_score, 'games', v_s.games, 'wins', v_s.wins,
    'losses', v_s.losses, 'streak', v_s.streak, 'best_streak', v_s.best_streak));
end;
$$;

-- Estatísticas do próprio jogador em todos os jogos.
create or replace function public.get_my_stats(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_pid bigint := public.retro_player_from_token(p_token);
  v_out jsonb;
begin
  if v_pid is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_session');
  end if;
  select coalesce(jsonb_object_agg(s.game, jsonb_build_object(
           'best_score', s.best_score, 'games', s.games, 'wins', s.wins,
           'losses', s.losses, 'streak', s.streak, 'best_streak', s.best_streak)),
         '{}'::jsonb)
    into v_out
    from public.game_stats s
   where s.player_id = v_pid;
  return jsonb_build_object('ok', true, 'stats', v_out);
end;
$$;

-- Hall of Fame global de um jogo: todos os jogadores registados (com zeros
-- quando ainda não jogaram). Só expõe nome e números, nunca ids nem PINs.
create or replace function public.get_leaderboard(p_game text, p_limit int default 500)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_out jsonb;
begin
  if p_game not in ('snake', 'forca', 'pacman', 'dino') then
    return '[]'::jsonb;
  end if;
  select coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) into v_out
    from (
      select p.username,
             coalesce(s.best_score, 0)  as best_score,
             coalesce(s.games, 0)       as games,
             coalesce(s.wins, 0)        as wins,
             coalesce(s.losses, 0)      as losses,
             coalesce(s.streak, 0)      as streak,
             coalesce(s.best_streak, 0) as best_streak
        from public.players p
        left join public.game_stats s
               on s.player_id = p.id and s.game = p_game
       order by case when p_game <> 'forca' then coalesce(s.best_score, 0)
                     else coalesce(s.wins, 0) end desc,
                p.created_at asc
       limit least(greatest(coalesce(p_limit, 500), 1), 500)
    ) t;
  return v_out;
end;
$$;

-- ---------------------------------------------------------------------------
-- Permissões: só as funções públicas ficam acessíveis ao navegador
-- ---------------------------------------------------------------------------

revoke all on function public.retro_key(text)                  from public, anon, authenticated;
revoke all on function public.retro_new_session(bigint)        from public, anon, authenticated;
revoke all on function public.retro_player_from_token(text)    from public, anon, authenticated;

revoke all on function public.register_player(text, text)      from public;
revoke all on function public.login_player(text, text)         from public;
revoke all on function public.check_session(text)              from public;
revoke all on function public.logout_player(text)              from public;
revoke all on function public.submit_result(text, text, int, text) from public;
revoke all on function public.get_my_stats(text)               from public;
revoke all on function public.get_leaderboard(text, int)       from public;

grant execute on function public.register_player(text, text)       to anon, authenticated;
grant execute on function public.login_player(text, text)          to anon, authenticated;
grant execute on function public.check_session(text)               to anon, authenticated;
grant execute on function public.logout_player(text)               to anon, authenticated;
grant execute on function public.submit_result(text, text, int, text) to anon, authenticated;
grant execute on function public.get_my_stats(text)                to anon, authenticated;
grant execute on function public.get_leaderboard(text, int)        to anon, authenticated;
