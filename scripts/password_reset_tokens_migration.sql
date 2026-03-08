CREATE TABLE IF NOT EXISTS public.password_reset_tokens (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  requested_ip text,
  user_agent text
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_active_idx
  ON public.password_reset_tokens (user_id, expires_at DESC)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_idx
  ON public.password_reset_tokens (expires_at);

COMMENT ON TABLE public.password_reset_tokens IS
  'Single-use password reset tokens. Store only SHA-256 token hashes.';
