BEGIN;

ALTER TABLE public.promo_codes
  ADD COLUMN IF NOT EXISTS applicable_categories text[];

UPDATE public.promo_codes
SET applicable_categories = ARRAY[]::text[]
WHERE applicable_categories IS NULL;

ALTER TABLE public.promo_codes
  ALTER COLUMN applicable_categories SET DEFAULT ARRAY[]::text[];

ALTER TABLE public.promo_codes
  ALTER COLUMN applicable_categories SET NOT NULL;

ALTER TABLE public.promo_codes
  DROP CONSTRAINT IF EXISTS promo_codes_applicable_categories_check;

ALTER TABLE public.promo_codes
  ADD CONSTRAINT promo_codes_applicable_categories_check
  CHECK (
    applicable_categories <@ ARRAY['book', 'magazine', 'subscription', 'supplement']::text[]
  );

COMMIT;
