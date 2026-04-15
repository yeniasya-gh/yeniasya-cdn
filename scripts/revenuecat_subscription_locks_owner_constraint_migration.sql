BEGIN;

DROP INDEX IF EXISTS public.revenuecat_subscription_locks_entitlement_owner_key_idx;

ALTER TABLE public.revenuecat_subscription_locks
  ADD CONSTRAINT revenuecat_subscription_locks_entitlement_owner_key_uniq
  UNIQUE (entitlement_id, owner_original_app_user_id);

COMMIT;
