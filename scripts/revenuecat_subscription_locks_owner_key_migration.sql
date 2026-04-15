BEGIN;

ALTER TABLE public.revenuecat_subscription_locks
  DROP CONSTRAINT IF EXISTS revenuecat_subscription_locks_entitlement_id_key;

UPDATE public.revenuecat_subscription_locks
SET owner_original_app_user_id = COALESCE(
  NULLIF(btrim(owner_original_app_user_id), ''),
  owner_app_user_id
)
WHERE owner_original_app_user_id IS NULL
   OR btrim(owner_original_app_user_id) = '';

ALTER TABLE public.revenuecat_subscription_locks
  ALTER COLUMN owner_original_app_user_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS revenuecat_subscription_locks_entitlement_owner_key_idx
  ON public.revenuecat_subscription_locks (entitlement_id, owner_original_app_user_id);

COMMIT;
