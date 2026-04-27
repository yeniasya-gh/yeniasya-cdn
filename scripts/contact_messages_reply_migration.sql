BEGIN;

ALTER TABLE public.contact_messages
  ADD COLUMN IF NOT EXISTS reply_message text;

ALTER TABLE public.contact_messages
  ADD COLUMN IF NOT EXISTS reply_at timestamptz;

ALTER TABLE public.contact_messages
  ADD COLUMN IF NOT EXISTS reply_admin_user_id bigint;

ALTER TABLE public.contact_messages
  DROP CONSTRAINT IF EXISTS contact_messages_reply_admin_user_id_fkey;

ALTER TABLE public.contact_messages
  ADD CONSTRAINT contact_messages_reply_admin_user_id_fkey
  FOREIGN KEY (reply_admin_user_id)
  REFERENCES public.users(id)
  ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS contact_messages_user_id_created_at_idx
  ON public.contact_messages (user_id, created_at DESC, id DESC);

COMMIT;
