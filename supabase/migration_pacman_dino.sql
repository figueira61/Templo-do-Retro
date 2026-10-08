-- ============================================================================
-- Migração: acrescenta os jogos 'pacman' e 'dino' ao Templo do Retro.
-- Supabase > SQL Editor > New query > colar tudo > Run. Pode correr-se várias vezes.
-- ============================================================================

alter table public.game_stats drop constraint if exists game_stats_game_check;
alter table public.game_stats add constraint game_stats_game_check
  check (game in ('snake', 'forca', 'pacman', 'dino'));

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
