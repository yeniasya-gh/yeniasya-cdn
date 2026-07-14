"use strict";

const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");

const DEFAULT_RSS_URL = "https://www.yeniasya.com.tr/rss/son-dakika";
const DEFAULT_STATE_FILE = path.resolve(
  process.cwd(),
  "data/news-portal-rss-state.json"
);
const FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const CATEGORY_ALIASES = new Map([
  ["kose-yazisi", "yazarlar"],
  ["video-galeri", "video"],
]);

function createNewsPortalRssNotificationService(options = {}) {
  return new NewsPortalRssNotificationService(options);
}

class NewsPortalRssNotificationService {
  constructor(options = {}) {
    this.rssUrl = options.rssUrl || process.env.NEWS_PORTAL_RSS_URL || DEFAULT_RSS_URL;
    this.stateFile =
      options.stateFile || process.env.NEWS_PORTAL_STATE_FILE || DEFAULT_STATE_FILE;
    this.delayRange = options.delayRange || readDelayRange();
    this.deliveryWindow = options.deliveryWindow || readDeliveryWindow();
    const dedicatedServiceAccountPath =
      options.serviceAccountPath || process.env.SONDAKIKA_FIREBASE_SERVICE_ACCOUNT;
    const dedicatedServiceAccountJson =
      options.serviceAccountJson || process.env.SONDAKIKA_FIREBASE_SERVICE_ACCOUNT_JSON;
    this.fcmClient =
      options.fcmClient ||
      new ServiceAccountFcmClient({
        serviceAccountPath:
          dedicatedServiceAccountPath ||
          process.env.FIREBASE_SERVICE_ACCOUNT_JSON_PATH ||
          process.env.GOOGLE_APPLICATION_CREDENTIALS,
        serviceAccountJson:
          dedicatedServiceAccountJson ||
          (dedicatedServiceAccountPath ? "" : process.env.FIREBASE_SERVICE_ACCOUNT_JSON),
      });
    this.now = options.now || (() => new Date());
  }

  async checkRssAndScheduleNotifications(options = {}) {
    const dryRun = options.dryRun === true;
    const persist = options.persist !== false;
    const seedWhenEmpty = options.seedWhenEmpty !== false;
    const state = await this.readState();
    const items = await fetchRssItems(this.rssUrl);
    const grouped = groupByCategory(items);
    const pending = [];
    const seenByCategory = state.seenByCategory || {};
    const skipped = [];
    const existingPendingIds = new Set(
      (state.pendingNotifications || []).map((item) => item.articleId)
    );
    const sentArticleIds = new Set(
      (state.sentNotifications || []).map((item) => item.articleId)
    );
    const categoriesWithPending = new Set(
      (state.pendingNotifications || []).map((item) => item.category)
    );

    for (const [categorySlug, categoryItems] of Object.entries(grouped)) {
      const currentIds = categoryItems.map((item) => item.articleId);
      const seen = new Set(seenByCategory[categorySlug] || []);

      if (seen.size === 0 && seedWhenEmpty) {
        seenByCategory[categorySlug] = currentIds.slice(0, 100);
        continue;
      }

      if (categoriesWithPending.has(categorySlug)) {
        skipped.push({
          category: categorySlug,
          reason: "category_has_pending_notification",
        });
        seenByCategory[categorySlug] = [
          ...currentIds,
          ...[...seen].filter((id) => !currentIds.includes(id)),
        ].slice(0, 120);
        continue;
      }

      const newItems = categoryItems.filter(
        (item) =>
          !seen.has(item.articleId) &&
          !existingPendingIds.has(item.articleId) &&
          !sentArticleIds.has(item.articleId)
      );
      if (newItems.length > 0) {
        const selected = chooseRandom(newItems);
        const scheduledAt = firstAllowedScheduledAt(this.now(), this.deliveryWindow);
        pending.push(createPendingNotification(selected, scheduledAt));
        existingPendingIds.add(selected.articleId);
        categoriesWithPending.add(categorySlug);
      }

      seenByCategory[categorySlug] = [
        ...currentIds,
        ...[...seen].filter((id) => !currentIds.includes(id)),
      ].slice(0, 120);
    }

    state.seenByCategory = seenByCategory;
    const newlyScheduledIds = new Set(pending.map((item) => item.articleId));
    state.pendingNotifications = spacePendingNotifications(
      [
      ...(state.pendingNotifications || []),
      ...pending,
      ],
      this.now(),
      this.delayRange,
      this.deliveryWindow,
      getLastSentAt(state)
    );
    state.updatedAt = this.now().toISOString();

    if (persist && !dryRun) {
      await this.writeState(state);
    }

    return {
      rssUrl: this.rssUrl,
      dryRun,
      fetchedCount: items.length,
      categoryCount: Object.keys(grouped).length,
      scheduledCount: pending.length,
      scheduled: state.pendingNotifications.filter((item) =>
        newlyScheduledIds.has(item.articleId)
      ),
      skipped,
      rules: notificationRules(this.delayRange, this.deliveryWindow),
    };
  }

  async dispatchDueNotifications(options = {}) {
    const dryRun = options.dryRun === true;
    const persist = options.persist !== false;
    const state = await this.readState();
    const now = this.now();
    const nowIso = now.toISOString();
    const pending = state.pendingNotifications || [];
    const due = pending.filter((item) => item.scheduledAt <= nowIso);
    const future = pending.filter((item) => item.scheduledAt > nowIso);
    const sent = [];
    const failed = [];

    if (!isWithinDeliveryWindow(now, this.deliveryWindow)) {
      state.pendingNotifications = spacePendingNotifications(
        pending,
        nextDeliveryWindowStart(now, this.deliveryWindow),
        this.delayRange,
        this.deliveryWindow,
        getLastSentAt(state)
      );
      state.updatedAt = nowIso;
      if (persist && state.pendingNotifications.length > 0) {
        await this.writeState(state);
      }
      return {
        dryRun,
        dueCount: due.length,
        sentCount: 0,
        failedCount: 0,
        sent,
        failed,
        outsideDeliveryWindow: true,
        deliveryWindow: formatDeliveryWindow(this.deliveryWindow),
      };
    }

    const dispatchable = due.slice(0, 1);
    const deferredDue = due.slice(1);

    for (const notification of dispatchable) {
      try {
        const response = await this.fcmClient.sendTopicMessage({
          topic: notification.topic,
          condition: buildNotificationCondition(notification.topic),
          notification: {
            title: notification.title,
            body: notification.body,
          },
          data: notification.data,
          dryRun,
        });
        sent.push({ ...notification, response });
      } catch (error) {
        failed.push({
          ...notification,
          error: error && error.message ? error.message : String(error),
        });
        future.push(notification);
      }
    }

    state.pendingNotifications = spacePendingNotifications(
      [...future, ...deferredDue, ...failed],
      now,
      this.delayRange,
      this.deliveryWindow,
      sent.length > 0 ? now : getLastSentAt(state)
    );
    state.sentNotifications = [
      ...sent.map((item) => ({
        articleId: item.articleId,
        topic: item.topic,
        category: item.category,
        title: item.title,
        url: item.data?.url || "",
        sentAt: nowIso,
        dryRun,
      })),
      ...(state.sentNotifications || []),
    ].slice(0, 500);
    if (sent.length > 0) {
      state.lastSentAt = nowIso;
    }
    state.updatedAt = nowIso;

    if (persist && (!dryRun || sent.length === 0)) {
      await this.writeState(state);
    }

    return {
      dryRun,
      dueCount: due.length,
      sentCount: sent.length,
      failedCount: failed.length,
      deferredCount: deferredDue.length,
      sent,
      failed,
      deliveryWindow: formatDeliveryWindow(this.deliveryWindow),
    };
  }

  async readState() {
    try {
      const raw = await fs.readFile(this.stateFile, "utf8");
      if (!raw.trim()) {
        return createEmptyState();
      }
      const parsed = JSON.parse(raw);
      return {
        seenByCategory: parsed.seenByCategory || {},
        pendingNotifications: parsed.pendingNotifications || [],
        sentNotifications: parsed.sentNotifications || [],
        lastSentAt: parsed.lastSentAt || null,
        updatedAt: parsed.updatedAt || null,
      };
    } catch (error) {
      if (error && error.code === "ENOENT") {
        return createEmptyState();
      }
      if (error instanceof SyntaxError) {
        console.error(
          `[news-portal-rss][state][invalid-json] file=${this.stateFile} msg=${error.message}`
        );
        return createEmptyState();
      }
      if (error && error.code !== "ENOENT") {
        throw error;
      }
      return createEmptyState();
    }
  }

  async writeState(state) {
    await fs.mkdir(path.dirname(this.stateFile), { recursive: true });
    await fs.writeFile(this.stateFile, `${JSON.stringify(state, null, 2)}\n`);
  }
}

function createEmptyState() {
  return {
    seenByCategory: {},
    pendingNotifications: [],
    sentNotifications: [],
    lastSentAt: null,
    updatedAt: null,
  };
}

class ServiceAccountFcmClient {
  constructor(options = {}) {
    this.serviceAccountPath = options.serviceAccountPath;
    this.serviceAccountJson = options.serviceAccountJson;
    this.cachedToken = null;
  }

  async sendTopicMessage({
    topic,
    condition,
    notification,
    data,
    dryRun = false,
  }) {
    const serviceAccount = await this.loadServiceAccount();
    const accessToken = await this.getAccessToken(serviceAccount);
    const response = await fetch(
      `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(
        serviceAccount.project_id
      )}/messages:send`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          validate_only: !!dryRun,
          message: {
            ...(condition ? { condition } : { topic }),
            notification,
            data: stringifyData(data),
            android: {
              priority: "HIGH",
              notification: {
                channel_id: "news_updates",
                default_sound: true,
              },
            },
            apns: {
              headers: {
                "apns-priority": "10",
              },
              payload: {
                aps: {
                  sound: "default",
                },
              },
            },
          },
        }),
      }
    );

    const body = await response.text();
    const decoded = body ? JSON.parse(body) : {};
    if (!response.ok) {
      throw new Error(`FCM_SEND_FAILED ${response.status}: ${body}`);
    }
    return decoded;
  }

  async loadServiceAccount() {
    if (this.serviceAccountJson) {
      return JSON.parse(this.serviceAccountJson);
    }
    if (!this.serviceAccountPath) {
      throw new Error(
        "SONDAKIKA_FIREBASE_SERVICE_ACCOUNT, FIREBASE_SERVICE_ACCOUNT_JSON_PATH veya GOOGLE_APPLICATION_CREDENTIALS gerekli."
      );
    }
    return JSON.parse(await fs.readFile(this.serviceAccountPath, "utf8"));
  }

  async getAccessToken(serviceAccount) {
    const now = Math.floor(Date.now() / 1000);
    if (this.cachedToken && this.cachedToken.expiresAt - 60 > now) {
      return this.cachedToken.accessToken;
    }

    const assertion = createServiceAccountJwt(serviceAccount, now);
    const response = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion,
      }),
    });
    const decoded = await response.json();
    if (!response.ok) {
      throw new Error(`FCM_TOKEN_FAILED ${response.status}: ${JSON.stringify(decoded)}`);
    }
    this.cachedToken = {
      accessToken: decoded.access_token,
      expiresAt: now + Number(decoded.expires_in || 3600),
    };
    return this.cachedToken.accessToken;
  }
}

function buildNotificationCondition(topic) {
  const normalizedTopic = String(topic || "").trim();
  if (!normalizedTopic || normalizedTopic === "breaking_all") {
    return "'breaking_all' in topics";
  }
  return `'breaking_all' in topics || '${normalizedTopic}' in topics`;
}

function notificationRules(
  delayRange = readDelayRange(),
  deliveryWindow = readDeliveryWindow()
) {
  return {
    rssUrl: DEFAULT_RSS_URL,
    checkFrequency: "hourly",
    dispatchFrequency: "every_minute",
    deliveryWindow: formatDeliveryWindow(deliveryWindow),
    target: "fcm_topic_per_category",
    topicPattern: "feed_<category-slug>",
    firstRun: "seed_existing_items_without_sending",
    perCategory: {
      maxScheduledPerCheck: 1,
      maxPendingAtAnyTime: 1,
      selection: "random_new_item",
    },
    randomDelayMinutes: {
      min: delayRange[0],
      max: delayRange[1],
    },
    dispatchPolicy: {
      maxPerDispatch: 1,
      newItems: "schedule_immediately_when_inside_delivery_window",
      pendingBacklog: "spread_with_random_gap_inside_delivery_window",
    },
    duplicatePrevention: {
      seenArticleIdsPerCategory: 120,
      sentHistoryLimit: 500,
    },
  };
}

async function fetchRssItems(rssUrl) {
  const response = await fetchWithRetry(rssUrl, {
    attempts: 3,
    timeoutMs: 20_000,
    retryDelayMs: 2_000,
    headers: {
      "user-agent": "YeniAsyaHaberPortaliBackend/1.0 RSS notifier",
      accept: "application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
    },
  });
  if (!response.ok) {
    throw new Error(`RSS_FETCH_FAILED ${response.status}`);
  }
  return parseRssItems(await response.text());
}

async function fetchWithRetry(url, options = {}) {
  const attempts = Math.max(1, Number(options.attempts || 1));
  const timeoutMs = Math.max(1_000, Number(options.timeoutMs || 20_000));
  const retryDelayMs = Math.max(0, Number(options.retryDelayMs || 0));
  let lastError = null;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, {
        headers: options.headers,
        signal: controller.signal,
      });
    } catch (error) {
      lastError = error;
      if (attempt >= attempts) break;
      await sleep(retryDelayMs * attempt);
    } finally {
      clearTimeout(timeout);
    }
  }

  throw lastError || new Error("RSS_FETCH_FAILED");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseRssItems(xml) {
  return matchAll(xml, /<item\b[^>]*>([\s\S]*?)<\/item>/gi)
    .map((itemXml) => parseRssItem(itemXml))
    .filter(Boolean);
}

function parseRssItem(itemXml) {
  const link = readXmlText(itemXml, "link");
  if (!link) return null;

  const title = readXmlText(itemXml, "title") || "Yeni Asya";
  const descriptionHtml = readXmlText(itemXml, "description") || "";
  const categoryText = readXmlText(itemXml, "category") || "Son Dakika";
  const imageUrl =
    readEnclosureUrl(itemXml) ||
    readMediaContentUrl(itemXml) ||
    readFirstImageUrl(descriptionHtml);
  const detailUrl = normalizeUrl(link);
  const categorySlug = normalizeCategorySlug(categoryText);

  return {
    guid: readXmlText(itemXml, "guid") || detailUrl,
    articleId: sha1Hex(detailUrl),
    title: cleanupText(title),
    summary: extractSummary(descriptionHtml),
    detailUrl,
    category: {
      raw: cleanupText(categoryText),
      slug: categorySlug,
      topic: `feed_${categorySlug}`,
    },
    imageUrl,
    publishedAt: readXmlText(itemXml, "pubDate") || null,
  };
}

function groupByCategory(items) {
  return items.reduce((acc, item) => {
    const slug = item.category.slug;
    if (!acc[slug]) acc[slug] = [];
    acc[slug].push(item);
    return acc;
  }, {});
}

function createPendingNotification(item, scheduledAt) {
  return {
    articleId: item.articleId,
    topic: item.category.topic,
    category: item.category.slug,
    title: item.title,
    body: buildNotificationBody(item),
    scheduledAt: scheduledAt.toISOString(),
    data: {
      url: item.detailUrl,
      title: item.title,
      category: item.category.slug,
      imageUrl: item.imageUrl || "",
      summary: item.summary,
    },
  };
}

function buildNotificationBody(item) {
  const categoryLabel = item.category.raw || "Yeni Asya";
  const body = item.summary || categoryLabel || "Yeni haber yayında.";
  return truncate(`${categoryLabel} • ${body}`, 140);
}

function randomScheduledAt(now, range) {
  const min = Math.max(0, Number(range[0]));
  const max = Math.max(min, Number(range[1]));
  const offset = min + Math.floor(Math.random() * (max - min + 1));
  return new Date(now.getTime() + offset * 60_000);
}

function firstAllowedScheduledAt(now, deliveryWindow = readDeliveryWindow()) {
  return isWithinDeliveryWindow(now, deliveryWindow)
    ? new Date(now.getTime())
    : nextDeliveryWindowStart(now, deliveryWindow);
}

function spacePendingNotifications(
  pending,
  now,
  range,
  deliveryWindow = readDeliveryWindow(),
  lastSentAt = null
) {
  const sorted = [...(pending || [])].sort((a, b) =>
    String(a.scheduledAt || "").localeCompare(String(b.scheduledAt || ""))
  );
  const spaced = [];
  let cursor = lastSentAt instanceof Date && !Number.isNaN(lastSentAt.getTime())
    ? lastSentAt
    : null;
  const floor = now instanceof Date ? now : new Date(now);

  for (const notification of sorted) {
    let scheduledAt = parseDateOrFallback(notification.scheduledAt, floor);
    if (scheduledAt < floor) {
      scheduledAt = new Date(floor.getTime());
    }
    scheduledAt = clampToDeliveryWindow(scheduledAt, deliveryWindow);

    if (cursor) {
      const earliest = randomScheduledAt(cursor, range);
      if (scheduledAt < earliest) {
        scheduledAt = clampToDeliveryWindow(earliest, deliveryWindow);
      }
    }

    cursor = scheduledAt;
    spaced.push({
      ...notification,
      scheduledAt: scheduledAt.toISOString(),
    });
  }

  return spaced.sort((a, b) => a.scheduledAt.localeCompare(b.scheduledAt));
}

function parseDateOrFallback(value, fallback) {
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed;
  }
  return new Date(fallback.getTime());
}

function clampToDeliveryWindow(value, deliveryWindow = readDeliveryWindow()) {
  const date = parseDateOrFallback(value, new Date());
  if (isWithinDeliveryWindow(date, deliveryWindow)) {
    return date;
  }
  return nextDeliveryWindowStart(date, deliveryWindow);
}

function isWithinDeliveryWindow(date, deliveryWindow = readDeliveryWindow()) {
  const minutes = date.getHours() * 60 + date.getMinutes();
  const { startMinutes, endMinutes } = deliveryWindow;
  if (startMinutes === endMinutes) return true;
  if (startMinutes < endMinutes) {
    return minutes >= startMinutes && minutes < endMinutes;
  }
  return minutes >= startMinutes || minutes < endMinutes;
}

function nextDeliveryWindowStart(date, deliveryWindow = readDeliveryWindow()) {
  const next = new Date(date.getTime());
  const minutes = next.getHours() * 60 + next.getMinutes();
  const { startMinutes, endMinutes } = deliveryWindow;

  if (startMinutes === endMinutes) {
    return next;
  }

  if (startMinutes < endMinutes) {
    if (minutes < startMinutes) {
      setLocalMinutesOfDay(next, startMinutes);
      return next;
    }
    next.setDate(next.getDate() + 1);
    setLocalMinutesOfDay(next, startMinutes);
    return next;
  }

  if (minutes >= endMinutes && minutes < startMinutes) {
    setLocalMinutesOfDay(next, startMinutes);
    return next;
  }
  next.setDate(next.getDate() + 1);
  setLocalMinutesOfDay(next, startMinutes);
  return next;
}

function setLocalMinutesOfDay(date, minutesOfDay) {
  date.setHours(Math.floor(minutesOfDay / 60), minutesOfDay % 60, 0, 0);
}

function readDeliveryWindow() {
  const raw = process.env.NEWS_PORTAL_DELIVERY_WINDOW || "08:00,00:00";
  const [startRaw, endRaw] = raw.split(",");
  return {
    startMinutes: parseClockMinutes(startRaw || "08:00"),
    endMinutes: normalizeEndClockMinutes(parseClockMinutes(endRaw || "00:00")),
  };
}

function parseClockMinutes(value) {
  const [hourRaw, minuteRaw] = String(value || "").trim().split(":");
  const hour = Number.parseInt(hourRaw || "0", 10);
  const minute = Number.parseInt(minuteRaw || "0", 10);
  if (!Number.isFinite(hour) || hour < 0 || hour > 24) return 0;
  if (!Number.isFinite(minute) || minute < 0 || minute > 59) return 0;
  return Math.min(24 * 60, hour * 60 + minute);
}

function normalizeEndClockMinutes(minutes) {
  return minutes === 0 ? 24 * 60 : minutes;
}

function formatDeliveryWindow(deliveryWindow = readDeliveryWindow()) {
  return `${formatClockMinutes(deliveryWindow.startMinutes)}-${formatClockMinutes(
    deliveryWindow.endMinutes === 24 * 60 ? 0 : deliveryWindow.endMinutes
  )}`;
}

function formatClockMinutes(minutes) {
  const normalized = ((minutes % (24 * 60)) + 24 * 60) % (24 * 60);
  return `${String(Math.floor(normalized / 60)).padStart(2, "0")}:${String(
    normalized % 60
  ).padStart(2, "0")}`;
}

function getLastSentAt(state) {
  const explicit = parseDateOrNull(state && state.lastSentAt);
  if (explicit) return explicit;
  const lastHistory = (state && state.sentNotifications || [])
    .map((item) => parseDateOrNull(item.sentAt))
    .filter(Boolean)
    .sort((a, b) => b.getTime() - a.getTime())[0];
  return lastHistory || null;
}

function parseDateOrNull(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function createServiceAccountJwt(serviceAccount, nowSeconds) {
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: serviceAccount.client_email,
    scope: FCM_SCOPE,
    aud: TOKEN_URL,
    exp: nowSeconds + 3600,
    iat: nowSeconds,
    sub: serviceAccount.client_email,
  };
  const unsigned = `${base64UrlJson(header)}.${base64UrlJson(claims)}`;
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(unsigned)
    .sign(serviceAccount.private_key);
  return `${unsigned}.${base64Url(signature)}`;
}

function readDelayRange() {
  const raw =
    process.env.NEWS_PORTAL_RANDOM_DELAY_MINUTES ||
    process.env.NEWS_PORTAL_DELAY_MINUTES ||
    "8,18";
  const [minRaw, maxRaw] = raw.split(",");
  const min = Number.parseInt(minRaw || "5", 10);
  const max = Number.parseInt(maxRaw || "55", 10);
  return [Number.isFinite(min) ? min : 5, Number.isFinite(max) ? max : 55];
}

function chooseRandom(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function readXmlText(xml, tagName) {
  const pattern = new RegExp(`<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`, "i");
  const match = xml.match(pattern);
  return match ? decodeXml(match[1]).trim() : "";
}

function readEnclosureUrl(xml) {
  const match = xml.match(/<enclosure\b[^>]*\burl=["']([^"']+)["'][^>]*>/i);
  return match ? normalizeUrl(decodeXml(match[1])) : null;
}

function readMediaContentUrl(xml) {
  const match = xml.match(/<(?:media:)?content\b[^>]*\burl=["']([^"']+)["'][^>]*>/i);
  return match ? normalizeUrl(decodeXml(match[1])) : null;
}

function readFirstImageUrl(html) {
  const match = html.match(/<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/i);
  return match ? normalizeUrl(decodeXml(match[1])) : null;
}

function normalizeUrl(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("http")) return trimmed;
  if (trimmed.startsWith("/")) return `https://www.yeniasya.com.tr${trimmed}`;
  return trimmed;
}

function normalizeCategorySlug(value) {
  const normalized = cleanupText(value)
    .toLocaleLowerCase("tr-TR")
    .replaceAll("ı", "i")
    .replaceAll("ğ", "g")
    .replaceAll("ü", "u")
    .replaceAll("ş", "s")
    .replaceAll("ö", "o")
    .replaceAll("ç", "c")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return CATEGORY_ALIASES.get(normalized) || normalized || "son-dakika";
}

function extractSummary(html) {
  return cleanupText(
    decodeXml(String(html || "").replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ")
  );
}

function cleanupText(value) {
  return decodeXml(String(value || ""))
    .replace(/\s+/g, " ")
    .trim();
}

function decodeXml(value) {
  return String(value || "")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&#x([0-9a-f]+);/gi, (_, raw) =>
      String.fromCodePoint(Number.parseInt(raw, 16))
    )
    .replace(/&#([0-9]+);/g, (_, raw) =>
      String.fromCodePoint(Number.parseInt(raw, 10))
    )
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#039;", "'")
    .replaceAll("&apos;", "'");
}

function matchAll(value, pattern) {
  const result = [];
  let match;
  while ((match = pattern.exec(value)) !== null) {
    result.push(match[1]);
  }
  return result;
}

function truncate(value, maxLength) {
  const text = cleanupText(value);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 1).trimEnd()}…`;
}

function sha1Hex(value) {
  return crypto.createHash("sha1").update(value, "utf8").digest("hex");
}

function stringifyData(data) {
  return Object.fromEntries(
    Object.entries(data || {}).map(([key, value]) => [key, String(value || "")])
  );
}

function base64UrlJson(value) {
  return base64Url(Buffer.from(JSON.stringify(value), "utf8"));
}

function base64Url(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
}

module.exports = {
  CATEGORY_ALIASES,
  DEFAULT_RSS_URL,
  NewsPortalRssNotificationService,
  ServiceAccountFcmClient,
  buildNotificationBody,
  createNewsPortalRssNotificationService,
  createPendingNotification,
  fetchRssItems,
  groupByCategory,
  notificationRules,
  firstAllowedScheduledAt,
  buildNotificationCondition,
  isWithinDeliveryWindow,
  normalizeCategorySlug,
  parseRssItem,
  parseRssItems,
  randomScheduledAt,
  spacePendingNotifications,
};
