BEGIN;

CREATE TABLE IF NOT EXISTS public.revenuecat_subscription_locks (
  id bigserial PRIMARY KEY,
  entitlement_id text NOT NULL UNIQUE,
  owner_user_id bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  owner_app_user_id text NOT NULL,
  owner_original_app_user_id text,
  product_identifier text,
  is_active boolean NOT NULL DEFAULT true,
  expires_at timestamptz,
  locked_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS revenuecat_subscription_locks_owner_user_idx
  ON public.revenuecat_subscription_locks (owner_user_id, is_active);

CREATE INDEX IF NOT EXISTS revenuecat_subscription_locks_active_expires_idx
  ON public.revenuecat_subscription_locks (is_active, expires_at DESC);

CREATE OR REPLACE FUNCTION public.set_revenuecat_subscription_locks_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_revenuecat_subscription_locks_updated_at
  ON public.revenuecat_subscription_locks;

CREATE TRIGGER trg_revenuecat_subscription_locks_updated_at
BEFORE UPDATE ON public.revenuecat_subscription_locks
FOR EACH ROW
EXECUTE FUNCTION public.set_revenuecat_subscription_locks_updated_at();

DO $$
DECLARE
  lock_owner_user_id bigint;
  seed_user_id bigint;
  seed_app_user_id text;
  seed_original_app_user_id text;
  seed_expires_at timestamptz;
BEGIN
  SELECT owner_user_id
  INTO lock_owner_user_id
  FROM public.revenuecat_subscription_locks
  WHERE entitlement_id = 'yeniasya pro'
  LIMIT 1;

  IF NOT FOUND THEN
    SELECT
      uca.user_id,
      COALESCE(NULLIF(btrim(u."payUniqe"), ''), uca.user_id::text) AS app_user_id,
      COALESCE(NULLIF(btrim(u."payUniqe"), ''), uca.user_id::text) AS original_app_user_id,
      uca.expires_at
    INTO seed_user_id, seed_app_user_id, seed_original_app_user_id, seed_expires_at
    FROM public.user_content_access uca
    JOIN public.users u
      ON u.id = uca.user_id
    WHERE uca.item_type = 'newspaper_subscription'::public.access_item_type
      AND uca.item_id IS NULL
      AND uca.is_active = true
      AND COALESCE(NULLIF(btrim(uca.grant_source), ''), 'revenuecat') = 'revenuecat'
    ORDER BY COALESCE(uca.started_at, uca.created_at, now()) ASC, uca.id ASC
    LIMIT 1;

    IF FOUND THEN
      INSERT INTO public.revenuecat_subscription_locks (
        entitlement_id,
        owner_user_id,
        owner_app_user_id,
        owner_original_app_user_id,
        product_identifier,
        is_active,
        expires_at,
        locked_at,
        updated_at,
        last_seen_at
      ) VALUES (
        'yeniasya pro',
        seed_user_id,
        seed_app_user_id,
        seed_original_app_user_id,
        NULL,
        true,
        seed_expires_at,
        now(),
        now(),
        now()
      )
      ON CONFLICT (entitlement_id) DO UPDATE SET
        owner_user_id = EXCLUDED.owner_user_id,
        owner_app_user_id = EXCLUDED.owner_app_user_id,
        owner_original_app_user_id = EXCLUDED.owner_original_app_user_id,
        product_identifier = EXCLUDED.product_identifier,
        is_active = EXCLUDED.is_active,
        expires_at = EXCLUDED.expires_at,
        last_seen_at = EXCLUDED.last_seen_at;
    END IF;
  END IF;

  SELECT owner_user_id
  INTO lock_owner_user_id
  FROM public.revenuecat_subscription_locks
  WHERE entitlement_id = 'yeniasya pro'
  LIMIT 1;

  IF FOUND THEN
    UPDATE public.user_content_access uca
    SET
      is_active = false,
      expires_at = COALESCE(uca.expires_at, now())
    WHERE uca.item_type = 'newspaper_subscription'::public.access_item_type
      AND uca.item_id IS NULL
      AND uca.is_active = true
      AND COALESCE(NULLIF(btrim(uca.grant_source), ''), 'revenuecat') = 'revenuecat'
      AND uca.user_id <> lock_owner_user_id;
  END IF;
END $$;

COMMIT;
