CREATE TABLE IF NOT EXISTS public.app_version (
  "key" text PRIMARY KEY,
  value text NOT NULL
);

INSERT INTO public.app_version ("key", value)
VALUES
  ('android', '2.7.0+17'),
  ('ios', '2.7.0+17')
ON CONFLICT ("key")
DO UPDATE SET value = EXCLUDED.value;
