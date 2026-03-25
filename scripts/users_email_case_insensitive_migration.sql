BEGIN;

UPDATE public.users
SET email = lower(email)
WHERE email IS NOT NULL AND email <> lower(email);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique_idx
  ON public.users (lower(email));

COMMIT;
