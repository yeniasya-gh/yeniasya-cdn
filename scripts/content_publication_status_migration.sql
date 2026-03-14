ALTER TABLE public.books
ADD COLUMN IF NOT EXISTS is_published boolean NOT NULL DEFAULT true;

ALTER TABLE public.magazine_issue
ADD COLUMN IF NOT EXISTS is_published boolean NOT NULL DEFAULT true;

UPDATE public.books
SET is_published = true
WHERE is_published IS DISTINCT FROM true;

UPDATE public.magazine_issue
SET is_published = true
WHERE is_published IS DISTINCT FROM true;

