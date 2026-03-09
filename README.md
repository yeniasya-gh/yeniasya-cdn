# File API (Node.js)

Fotoğraf ve PDF yükleyebileceğiniz, public ve private alanları olan minimal API.

## Kurulum
1) Node 18+ kurulu olmalı.  
2) Ortam değişkenlerini ayarla:
```bash
cp .env.example .env
# AUTH_TOKEN, VIEW_TOKEN_SECRET, HASURA_ENDPOINT, HASURA_ADMIN_SECRET, JWT_SECRET zorunlu
# Mail (opsiyonel ama /mail/send ve /mail/welcome için gerekli):
# MAIL_HOST=smtp.example.com
# MAIL_PORT=587
# MAIL_USER=...
# MAIL_PASS=...
# MAIL_FROM="Yeni Asya Dijital <noreply@yeniasya.com.tr>"
# TLS sertifika CN/SAN host ile SMTP host farklıysa:
# MAIL_TLS_SERVERNAME=srvpanel.com
# MAIL_TLS_REJECT_UNAUTHORIZED=true
# (acil geçici bypass için false yapılabilir, önerilmez)
# MAIL_API_TOKEN=...
# Şifre sıfırlama linki:
# PASSWORD_RESET_WEB_URL=https://cdn.yeniasyadigital.com/sifre-sifirla
# PASSWORD_RESET_TOKEN_TTL_MINUTES=30
# PASSWORD_RESET_REQUEST_RATE_LIMIT_MAX=8
# PASSWORD_RESET_CONFIRM_RATE_LIMIT_MAX=10
# Origin yetkisi için ALLOWED_ORIGINS'i kendi domainlerinle doldur (virgülle ayır)
# Base64 viewer kapalıdır (istersen ENABLE_BASE64_VIEWER=true)
# İsteğe bağlı: MAX_BASE64_VIEW_BYTES=5242880
# JWT opsiyonelleri:
# JWT_EXPIRES_IN=1d
# JWT_ISSUER=yeniasya
# JWT_AUDIENCE=yeniasya-app
# JWT_DEFAULT_ROLE=user
# JWT_ALLOWED_ROLES=user
# Legacy e-gazete fallback (opsiyonel ama eski tarihleri açmak için gerekli):
# LEGACY_NEWSPAPER_PDF_BASE_URL=https://www.yeniasya.com.tr/Sites/YeniAsya/Upload/files/EPub
# Guest JWT opsiyonelleri:
# GUEST_JWT_ROLE=guest
# GUEST_JWT_ALLOWED_ROLES=guest
# GUEST_JWT_EXPIRES_IN=6h
# GUEST_TOKEN_RATE_LIMIT_MAX=120
# Admin push bildirim servisi (opsiyonel):
# FIREBASE_SERVICE_ACCOUNT_JSON_PATH=/absolute/path/firebase-service-account.json
# veya FIREBASE_SERVICE_ACCOUNT_JSON={"type":"service_account",...}
# FIREBASE_PROJECT_ID=<firebase-project-id>   # JSON içindeki project_id yoksa kullanılır
# ADMIN_ROLE_IDS=2                             # virgül ile birden fazla rol id verilebilir
# FCM_HTTP_TIMEOUT_MS=15000
# Opsiyonel (BunnyCDN isteklerini daha stabil yapmak için):
# BUNNY_HTTP_TIMEOUT_MS=20000
# BUNNY_HTTP_RETRIES=1
# BUNNY_HTTP_RETRY_BASE_DELAY_MS=400
# Stream endpoint'lerinde (private/view, private/:type/:filename) ilk byte / idle timeout:
# BUNNY_STREAM_FIRST_BYTE_TIMEOUT_MS=15000
# BUNNY_STREAM_IDLE_TIMEOUT_MS=30000
# BUNNY_DEBUG=true
```
3) Bağımlılıklar:
```bash
npm install
```
4) Çalıştır:
```bash
npm start
# veya değişiklik takipli
npm run dev
```

## Manuel E-Gazete Erişim Tablosu
- Eski sistem aboneleri için manuel erişim tablosu migration dosyası:
  `scripts/manual_newspaper_users_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/manual_newspaper_users_migration.sql
```
- Migration sonrası Hasura'da `manual_newspaper_users` tablosunu track edin.

## Şifre Sıfırlama Token Tablosu
- Migration dosyası:
  `scripts/password_reset_tokens_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/password_reset_tokens_migration.sql
```
- Migration sonrası Hasura'da `password_reset_tokens` tablosunu track edin.

## Endpoint'ler
- `POST /auth/register`
  - JSON body: `{ "name": "...", "email": "...", "password": "...", "phone": "..." }`
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/login`
  - JSON body: `{ "email": "...", "password": "..." }`
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/social-login`
  - JSON body: `{ "email": "...", "provider": "google|apple", "name": "...", "phone": "..." }`
  - Kullanıcı varsa JWT döner, yoksa `404 USER_NOT_FOUND`.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/guest-token`
  - Body zorunlu değildir.
  - CDN kısa ömürlü bir `guest` JWT üretir.
  - Bu token yalnızca Hasura'da `guest` rolüne verdiğiniz public izinler kadar erişim sağlamalıdır.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/password-reset/request`
  - JSON body: `{ "email": "..." }`
  - Güvenlik için kullanıcı kayıtlı olsun ya da olmasın aynı başarılı yanıtı döner.
  - Şifre sıfırlama bağlantısını `PASSWORD_RESET_WEB_URL` adresine üretir.
- `POST /auth/password-reset/confirm`
  - JSON body: `{ "token": "...", "password": "..." }`
  - Token tek kullanımlıktır; başarılı işlemden sonra aynı kullanıcıya ait açık tokenlar kapatılır.
- `POST /newspaper/view-url`
  - Auth: `Authorization: Bearer <JWT>`
  - JSON body: `{ "date": "YYYY-MM-DD" }`
  - Aktif e-gazete aboneliği olan kullanıcı için seçilen tarihin görüntüleme URL'ini döner.
  - Tarih `newspaper` tablosunda varsa sistemdeki `file_url` kullanılır.
  - Tarih sistemde yoksa eski sistemdeki doğrudan PDF URL'i üretilir.
  - Yanıt: `{ ok, date, url, isPrivate, source }`
- `POST /graphql`
  - Hasura proxy (JWT zorunlu).
  - Header: `Authorization: Bearer <JWT>`
  - JSON body: `{ "query": "...", "variables": { ... }, "operationName": "..." }`
- `POST /upload/public`  
  - Form-data alanları: `file` (foto/pdf), `type` (kitap|gazete|dergi|ek|slider).  
  - Dosya yolları: `storage/<type>/public/`.
  - Header: `x-api-key: <AUTH_TOKEN>` veya `Authorization: Bearer <AUTH_TOKEN>`.
- `POST /upload/private`  
  - Form-data: `file` ve `type` (kitap|gazete|dergi|ek).  
  - Dosya yolu: `storage/<type>/private/`.  
  - Yanıt `url` değeri: `/private/<type>/<filename>`.
  - Header: `x-api-key: <AUTH_TOKEN>` veya `Authorization: Bearer <AUTH_TOKEN>`.
- `GET /public/:type/:filename`  
  - Direkt erişim, auth yok.
- `GET /private/:type/:filename`  
  - Header: `x-api-key: <AUTH_TOKEN>` veya `Authorization: Bearer <AUTH_TOKEN>`.
- `POST /private/view`  
  - JSON body: `{"path": "/private/<type>/<file.pdf>"}` (pdf uzantısı zorunlu).  
  - Header: `x-api-key: <AUTH_TOKEN>` veya `Authorization: Bearer <AUTH_TOKEN>`.  
  - PDF inline açılır, cache kapalı, frame-ancestors ALLOWED_FRAME_ANCESTORS ile kontrol edilir.
- `GET /private/view-file`
  - Base64 viewer (varsayılan kapalı).  
  - Aktif etmek için `ENABLE_BASE64_VIEWER=true` ve opsiyonel `MAX_BASE64_VIEW_BYTES`.
- `POST /admin/notifications/send`
  - Auth: `Authorization: Bearer <JWT>` (admin rol) veya `x-api-key: <AUTH_TOKEN>`.
  - JSON body:
    - `title` (zorunlu)
    - `body` (zorunlu)
    - `userId` (opsiyonel, tek kullanıcı)
    - `userIds` (opsiyonel, kullanıcı id listesi)
    - `data` (opsiyonel, FCM data payload)
    - `persist` (opsiyonel, default `true`, başarılı gönderimler için `notifications` tablosuna kayıt)
    - `dryRun` (opsiyonel, default `false`)
  - Token kaynağı: `users.firebase_token`
- `POST /mail/welcome`
  - Auth: `Authorization: Bearer <JWT>`
  - Hoş geldin mailini yalnızca bir kez gönderir (kontrol alanı: `users.welcome_mail_sent_at`).
  - Not: Önce `scripts/welcome_mail_sent_at_migration.sql` çalıştırılmalıdır.
- `POST /mail/order-summary`
  - Auth: `Authorization: Bearer <JWT>`
  - Kullanıcının kendi hesabına sipariş özet maili gönderir.
  - JSON body: `{ "orderId": "...", "total": 123.45, "items": [{ "title": "...", "quantity": 1, "line_total": 123.45 }] }`
- `GET /health` durumu kontrol eder.

## Kurallar
- İzin verilen MIME: `application/pdf`, `image/jpeg`, `image/png`, `image/webp`.
- 50MB üstü dosyalar reddedilir.
- Private dosyalar `storage/<type>/private` dizinlerine yazılır.
- CORS: `.env` içinde `ALLOWED_ORIGINS` (örn. `http://localhost:3000,https://cdn.yeniasyadigital.com`) ve `ALLOWED_HEADERS` (varsayılan `content-type,x-api-key,authorization,x-mail-token`).
- Frame koruması: `.env` içinde `ALLOWED_FRAME_ANCESTORS` ile whitelist belirleyin.
- Ödeme test endpoint'i sadece `NODE_ENV=development` iken çalışır ve `TEST_MERCHANT`, `TEST_MERCHANTUSER`, `TEST_MERCHANTPASSWORD`, `TEST_RETURNURL` ister.

## Örnek istekler
```bash
# Public kitap yükle
curl -X POST http://localhost:3000/upload/public \
  -F "type=kitap" \
  -F "file=@/path/to/image.jpg"

# Gazete yükle
curl -X POST http://localhost:3000/upload/public \
  -F "type=gazete" \
  -F "file=@/path/to/file.pdf"

# Private kitap yükle
curl -X POST http://localhost:3000/upload/private \
  -F "type=kitap" \
  -F "file=@/path/to/secret.pdf"

# Private dosya çek
curl -H "x-api-key: <AUTH_TOKEN>" \
  http://localhost:3000/private/<filename>
```
