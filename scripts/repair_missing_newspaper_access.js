#!/usr/bin/env node

require("dotenv").config({ path: ".env" });

const { Client } = require("pg");

const args = new Set(process.argv.slice(2));
const apply = args.has("--apply");
const limitArg = [...args].find((arg) => arg.startsWith("--limit="));
const limit = limitArg ? Number.parseInt(limitArg.split("=")[1], 10) : null;

const toPositiveIntOrNull = (value) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
};

const parseMetadata = (metadata) => {
  if (!metadata) return {};
  if (typeof metadata === "object") return metadata;
  try {
    const parsed = JSON.parse(String(metadata));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (err) {
    return {};
  }
};

const getDurationMonths = (row) => {
  const metadata = parseMetadata(row.metadata);
  return toPositiveIntOrNull(
    metadata.durationMonths ||
      metadata.periodMonths ||
      metadata.period_months ||
      metadata.period ||
      row.type_duration_months
  );
};

const addMonthsIso = (dateValue, months) => {
  const date = new Date(dateValue || Date.now());
  if (Number.isNaN(date.getTime())) return null;
  date.setMonth(date.getMonth() + months);
  return date.toISOString();
};

const createClient = () =>
  new Client({
    host: process.env.HOME_POSTGRES_HOST,
    port: process.env.HOME_POSTGRES_PORT,
    database: process.env.HOME_POSTGRES_DATABASE,
    user: process.env.HOME_POSTGRES_USER,
    password: process.env.HOME_POSTGRES_PASSWORD,
    ssl: false,
  });

const main = async () => {
  const client = createClient();
  await client.connect();

  const values = [];
  const limitSql = limit ? `LIMIT $${values.push(limit)}` : "";
  const { rows } = await client.query(
    `
      SELECT
        o.id::bigint AS order_id,
        o.user_id::bigint AS user_id,
        o.created_at AS order_created_at,
        o.status::text AS order_status,
        o.payment_approved,
        o.total_paid,
        oi.id::bigint AS order_item_id,
        oi.title,
        oi.quantity::int AS quantity,
        oi.unit_price,
        oi.line_total,
        oi.product_id::bigint AS product_id,
        oi.metadata,
        nst.duration_months::int AS type_duration_months,
        m.id::bigint AS manual_access_id,
        m.ends_at AS manual_ends_at,
        uca.id::bigint AS content_access_id,
        uca.expires_at AS content_expires_at
      FROM public.order_items oi
      JOIN public.orders o ON o.id = oi.order_id
      LEFT JOIN public.newspaper_subscription_type nst ON nst.id = oi.product_id
      LEFT JOIN public.manual_newspaper_users m
        ON m.user_id = o.user_id
       AND m.is_active = TRUE
       AND m.ends_at > now()
      LEFT JOIN public.user_content_access uca
        ON uca.user_id = o.user_id
       AND uca.item_type = 'newspaper_subscription'::public.access_item_type
       AND uca.is_active = TRUE
       AND (uca.expires_at IS NULL OR uca.expires_at > now())
      WHERE oi.product_type = 'newspaper_subscription'
        AND (
          o.payment_approved = TRUE
          OR lower(o.status::text) IN ('paid', 'approved', 'completed', 'success', 'successful')
        )
      ORDER BY o.created_at ASC, o.id ASC, oi.id ASC
      ${limitSql}
    `,
    values
  );

  const now = new Date();
  const candidates = [];
  const skipped = [];
  const seenUsers = new Set();

  for (const row of rows) {
    if (seenUsers.has(String(row.user_id))) {
      skipped.push({ user_id: row.user_id, order_id: row.order_id, reason: "duplicate_user_candidate" });
      continue;
    }

    if (row.manual_access_id || row.content_access_id) {
      skipped.push({ user_id: row.user_id, order_id: row.order_id, reason: "active_access_exists" });
      continue;
    }

    const durationMonths = getDurationMonths(row);
    if (!durationMonths) {
      skipped.push({ user_id: row.user_id, order_id: row.order_id, reason: "missing_duration_months" });
      continue;
    }

    const startsAt = new Date(row.order_created_at || now).toISOString();
    const endsAt = addMonthsIso(row.order_created_at || now, durationMonths);
    if (!endsAt || new Date(endsAt) <= now) {
      skipped.push({ user_id: row.user_id, order_id: row.order_id, reason: "computed_access_expired" });
      continue;
    }

    seenUsers.add(String(row.user_id));
    candidates.push({
      user_id: row.user_id,
      order_id: row.order_id,
      order_item_id: row.order_item_id,
      title: row.title,
      starts_at: startsAt,
      ends_at: endsAt,
      duration_months: durationMonths,
    });
  }

  const repaired = [];
  if (apply && candidates.length) {
    await client.query("BEGIN");
    try {
      for (const candidate of candidates) {
        const insert = await client.query(
          `
            INSERT INTO public.manual_newspaper_users AS m (
              user_id,
              starts_at,
              ends_at,
              is_active,
              status,
              note,
              created_at,
              updated_at
            ) VALUES (
              $1::bigint,
              $2::timestamptz,
              $3::timestamptz,
              TRUE,
              'new',
              $4::text,
              now(),
              now()
            )
            ON CONFLICT (user_id) DO UPDATE SET
              starts_at = LEAST(m.starts_at, EXCLUDED.starts_at),
              ends_at = GREATEST(m.ends_at, EXCLUDED.ends_at),
              is_active = TRUE,
              status = 'new',
              note = EXCLUDED.note,
              updated_at = now()
            RETURNING id::bigint AS id, user_id::bigint AS user_id, starts_at, ends_at, is_active, status
          `,
          [
            candidate.user_id,
            candidate.starts_at,
            candidate.ends_at,
            `Otomatik onarım: ödenmiş e-gazete siparişi erişime yansımamış. order_id=${candidate.order_id}`,
          ]
        );
        repaired.push({ ...candidate, manual_access: insert.rows[0] || null });
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  }

  await client.end();

  console.log(
    JSON.stringify(
      {
        mode: apply ? "apply" : "dry-run",
        scanned: rows.length,
        candidates: candidates.length,
        repaired: repaired.length,
        skipped: skipped.length,
        candidate_rows: candidates,
        repaired_rows: repaired,
        skipped_rows: skipped,
      },
      null,
      2
    )
  );
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
