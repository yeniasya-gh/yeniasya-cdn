BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS "payUniqe" text;

UPDATE public.users
SET "payUniqe" = gen_random_uuid()::text
WHERE "payUniqe" IS NULL OR btrim("payUniqe") = '';

WITH duplicated AS (
  SELECT
    id,
    row_number() OVER (PARTITION BY "payUniqe" ORDER BY id) AS rn
  FROM public.users
  WHERE "payUniqe" IS NOT NULL AND btrim("payUniqe") <> ''
)
UPDATE public.users u
SET "payUniqe" = gen_random_uuid()::text
FROM duplicated d
WHERE u.id = d.id AND d.rn > 1;

ALTER TABLE public.users
  ALTER COLUMN "payUniqe" SET DEFAULT gen_random_uuid()::text;

ALTER TABLE public.users
  ALTER COLUMN "payUniqe" SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_payuniqe_unique_idx
  ON public.users ("payUniqe");

DO $$
BEGIN
  ALTER TYPE public.access_item_type ADD VALUE IF NOT EXISTS 'newspaper_subscription';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

WITH ranked_access AS (
  SELECT
    id,
    row_number() OVER (
      PARTITION BY user_id, item_type
      ORDER BY started_at DESC NULLS LAST, id DESC
    ) AS rn
  FROM public.user_content_access
  WHERE item_type = 'newspaper_subscription'::public.access_item_type
    AND item_id IS NULL
    AND is_active = true
)
UPDATE public.user_content_access uca
SET
  is_active = false,
  expires_at = COALESCE(uca.expires_at, now())
FROM ranked_access ra
WHERE uca.id = ra.id
  AND ra.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS user_content_access_active_newspaper_subscription_uq
  ON public.user_content_access (user_id, item_type)
  WHERE item_type = 'newspaper_subscription'::public.access_item_type
    AND item_id IS NULL
    AND is_active = true;

CREATE INDEX IF NOT EXISTS user_content_access_user_item_type_idx
  ON public.user_content_access (user_id, item_type);

COMMIT;
