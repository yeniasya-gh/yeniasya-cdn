BEGIN;

ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS "payUniqe" text;

DO $$
DECLARE
  payuniqe_udt text;
BEGIN
  SELECT c.udt_name
  INTO payuniqe_udt
  FROM information_schema.columns c
  WHERE c.table_schema = 'public'
    AND c.table_name = 'users'
    AND c.column_name = 'payUniqe'
  LIMIT 1;

  IF payuniqe_udt IS NOT NULL AND payuniqe_udt <> 'text' THEN
    EXECUTE 'ALTER TABLE public.users ALTER COLUMN "payUniqe" TYPE text USING "payUniqe"::text';
  END IF;
END $$;

UPDATE public.users u
SET "payUniqe" = md5(
  random()::text || clock_timestamp()::text || txid_current()::text || u.id::text
)
WHERE u."payUniqe" IS NULL OR btrim(u."payUniqe") = '';

WITH duplicated AS (
  SELECT
    id,
    row_number() OVER (PARTITION BY "payUniqe" ORDER BY id) AS rn
  FROM public.users
  WHERE "payUniqe" IS NOT NULL AND btrim("payUniqe") <> ''
)
UPDATE public.users u
SET "payUniqe" = md5(
  random()::text || clock_timestamp()::text || txid_current()::text || u.id::text
)
FROM duplicated d
WHERE u.id = d.id AND d.rn > 1;

ALTER TABLE public.users
  ALTER COLUMN "payUniqe" SET DEFAULT md5(
    random()::text || clock_timestamp()::text || txid_current()::text
  );

ALTER TABLE public.users
  ALTER COLUMN "payUniqe" SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_payuniqe_unique_idx
  ON public.users ("payUniqe");

COMMIT;

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
