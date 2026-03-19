BEGIN;

ALTER TABLE public.user_content_access
  ADD COLUMN IF NOT EXISTS grant_source text;

CREATE INDEX IF NOT EXISTS user_content_access_newspaper_grant_source_idx
  ON public.user_content_access (item_type, grant_source, user_id)
  WHERE item_type = 'newspaper_subscription'::public.access_item_type
    AND item_id IS NULL;

COMMIT;
