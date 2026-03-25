BEGIN;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS auth_session_id text;

CREATE INDEX IF NOT EXISTS users_auth_session_id_idx
  ON public.users (auth_session_id);

COMMIT;
