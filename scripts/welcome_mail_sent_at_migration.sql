BEGIN;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS welcome_mail_sent_at timestamptz;

CREATE INDEX IF NOT EXISTS users_welcome_mail_sent_at_not_null_idx
  ON public.users (welcome_mail_sent_at)
  WHERE welcome_mail_sent_at IS NOT NULL;

COMMIT;
