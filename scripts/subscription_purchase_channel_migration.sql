BEGIN;

ALTER TABLE public.user_content_access
  ADD COLUMN IF NOT EXISTS purchase_platform text;

CREATE INDEX IF NOT EXISTS user_content_access_purchase_platform_idx
  ON public.user_content_access (item_type, purchase_platform, user_id)
  WHERE item_type = 'newspaper_subscription'::public.access_item_type
    AND item_id IS NULL;

ALTER TABLE public.orders
  ADD COLUMN IF NOT EXISTS payment_provider text;

CREATE INDEX IF NOT EXISTS orders_payment_provider_idx
  ON public.orders (payment_provider, created_at DESC);

UPDATE public.orders
SET payment_provider = 'paratika'
WHERE payment_provider IS NULL
  AND merchant_payment_id IS NOT NULL;

COMMIT;
