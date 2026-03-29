BEGIN;

CREATE TABLE IF NOT EXISTS public.manual_newspaper_users (
  id bigserial PRIMARY KEY,
  user_id bigint NOT NULL,
  starts_at timestamptz NOT NULL DEFAULT now(),
  ends_at timestamptz NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  status text NOT NULL DEFAULT 'new',
  note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT manual_newspaper_users_user_id_key UNIQUE (user_id),
  CONSTRAINT manual_newspaper_users_status_check CHECK (status IN ('old', 'new')),
  CONSTRAINT manual_newspaper_users_dates_check CHECK (ends_at > starts_at),
  CONSTRAINT manual_newspaper_users_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'manual_newspaper_users'
      AND column_name = 'status'
  ) THEN
    ALTER TABLE public.manual_newspaper_users
      ADD COLUMN status text;
  END IF;
END $$;

UPDATE public.manual_newspaper_users
SET status = 'new'
WHERE status IS NULL OR btrim(status) = '';

ALTER TABLE public.manual_newspaper_users
  ALTER COLUMN status SET DEFAULT 'new';

ALTER TABLE public.manual_newspaper_users
  ALTER COLUMN status SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'manual_newspaper_users_status_check'
  ) THEN
    ALTER TABLE public.manual_newspaper_users
      ADD CONSTRAINT manual_newspaper_users_status_check
      CHECK (status IN ('old', 'new'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS manual_newspaper_users_active_ends_idx
  ON public.manual_newspaper_users (is_active, ends_at DESC);

CREATE INDEX IF NOT EXISTS manual_newspaper_users_user_active_idx
  ON public.manual_newspaper_users (user_id, is_active, ends_at DESC);

CREATE INDEX IF NOT EXISTS manual_newspaper_users_status_active_idx
  ON public.manual_newspaper_users (status, is_active, ends_at DESC);

CREATE OR REPLACE FUNCTION public.set_manual_newspaper_users_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_manual_newspaper_users_updated_at
  ON public.manual_newspaper_users;

CREATE TRIGGER trg_manual_newspaper_users_updated_at
BEFORE UPDATE ON public.manual_newspaper_users
FOR EACH ROW
EXECUTE FUNCTION public.set_manual_newspaper_users_updated_at();

COMMIT;
