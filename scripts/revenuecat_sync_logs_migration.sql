BEGIN;

CREATE TABLE IF NOT EXISTS public.revenuecat_sync_logs (
  id bigserial PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  request_id text NOT NULL,
  endpoint text NOT NULL,
  source text,
  event_type text,
  result text,
  success boolean NOT NULL DEFAULT true,
  auth_mode text,
  user_id bigint,
  app_user_id text,
  expected_app_user_id text,
  identity_payload_matched boolean,
  identity_server_matched boolean,
  identity_effective_matched boolean,
  entitlement_id text,
  is_active boolean,
  expiration_date timestamptz,
  verification_source text,
  verification_reason text,
  access_action text,
  error text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS revenuecat_sync_logs_created_at_idx
  ON public.revenuecat_sync_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS revenuecat_sync_logs_request_id_idx
  ON public.revenuecat_sync_logs (request_id);

CREATE INDEX IF NOT EXISTS revenuecat_sync_logs_user_id_created_idx
  ON public.revenuecat_sync_logs (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS revenuecat_sync_logs_app_user_id_created_idx
  ON public.revenuecat_sync_logs (app_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS revenuecat_sync_logs_endpoint_created_idx
  ON public.revenuecat_sync_logs (endpoint, created_at DESC);

COMMIT;
