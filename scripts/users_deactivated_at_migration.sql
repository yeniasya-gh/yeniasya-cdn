ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS deactivated_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_users_is_active_deactivated_at
  ON public.users (is_active, deactivated_at DESC);
