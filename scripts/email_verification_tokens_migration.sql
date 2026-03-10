ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS email_verified_at timestamptz;

UPDATE public.users
SET email_verified_at = now()
WHERE email_verified_at IS NULL;

CREATE TABLE IF NOT EXISTS public.email_verification_tokens (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  requested_ip text,
  user_agent text
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_active_idx
  ON public.email_verification_tokens (user_id, expires_at DESC)
  WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_idx
  ON public.email_verification_tokens (expires_at);

COMMENT ON TABLE public.email_verification_tokens IS
  'Single-use email verification tokens. Store only SHA-256 token hashes.';
