ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS avatar_url text;

COMMENT ON COLUMN public.users.avatar_url IS
  'Public profile avatar image URL stored on BunnyCDN.';
