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
# PASSWORD_RESET_WEB_URL=https://cdn.yeniasyadijital.com/sifre-sifirla
# PASSWORD_RESET_TOKEN_TTL_MINUTES=30
# Hesap aktivasyon linki:
# EMAIL_VERIFICATION_WEB_URL=https://yeniasyadijital.com/hesap-aktivasyon
# EMAIL_VERIFICATION_TOKEN_TTL_MINUTES=60
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
# Anasayfa Postgres (Hasura yerine direkt DB erişimi):
# HOME_POSTGRES_URL=postgres://user:pass@host:5432/dbname
# veya ayrı alanlarla:
# HOME_POSTGRES_HOST=localhost
# HOME_POSTGRES_PORT=5432
# HOME_POSTGRES_DATABASE=yeniasya
# HOME_POSTGRES_USER=postgres
# HOME_POSTGRES_PASSWORD=...
# HOME_POSTGRES_SSL=true
# HOME_POSTGRES_SSL_REJECT_UNAUTHORIZED=true
# HOME_POSTGRES_QUERY_TIMEOUT_MS=10000
# HOME_POSTGRES_POOL_MAX=10
# RevenueCat gazete erişim reconcile job (opsiyonel, varsayılan açık):
# REVENUECAT_RECONCILE_ENABLED=true
# REVENUECAT_RECONCILE_INTERVAL_MINUTES=30
# REVENUECAT_RECONCILE_BATCH_SIZE=50
# REVENUECAT_RECONCILE_STARTUP_DELAY_MS=15000
# REVENUECAT_SYNC_DELETE_EXPIRY_GRACE_MS=300000
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
# CDN_PUBLIC_HOST=cdn.yeniasyadijital.com
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

## RevenueCat Gazete Erişim Kaynağı
- Migration dosyası:
  `scripts/revenuecat_access_source_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/revenuecat_access_source_migration.sql
```
- Not:
  `user_content_access.grant_source` kolonu RevenueCat tarafından yönetilen `newspaper_subscription`
  kayıtlarını işaretlemek için kullanılır. CDN job'ı bu bilgiyle biten RC aboneliklerini güvenli
  şekilde temizler; manuel verilen gazete erişimleri korunur.

## Şifre Sıfırlama Token Tablosu
- Migration dosyası:
  `scripts/password_reset_tokens_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/password_reset_tokens_migration.sql
```
- Migration sonrası Hasura'da `password_reset_tokens` tablosunu track edin.

## E-Posta Aktivasyon Token Tablosu
- Migration dosyası:
  `scripts/email_verification_tokens_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/email_verification_tokens_migration.sql
```
- Migration sonrası Hasura'da `email_verification_tokens` tablosunu track edin.

## Kullanıcı Profil Fotoğrafı Kolonu
- Migration dosyası:
  `scripts/users_avatar_url_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/users_avatar_url_migration.sql
```
- Not:
  `users.avatar_url` kolonu CDN üzerinde profil fotoğrafı URL'ini tutar.

## E-Posta Case-Insensitive Unique
- Migration dosyası:
  `scripts/users_email_case_insensitive_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/users_email_case_insensitive_migration.sql
```
- Not:
  Kayıt ve giriş akışları e-posta adresini küçük harfe normalize eder.
  Bu migration mevcut e-posta kayıtlarını küçük harfe çevirir ve `lower(email)` üzerinde unique index oluşturur.
  Böylece `Pazarlama@...` ile `pazarlama@...` aynı hesap olarak değerlendirilir.

## İçerik Yayın Durumu Kolonları
- Migration dosyası:
  `scripts/content_publication_status_migration.sql`
- Uygulama:
```bash
psql "$DATABASE_URL" -f scripts/content_publication_status_migration.sql
```
- Not:
  `books.is_published` ve `magazine_issue.is_published` alanları public listelerde görünürlüğü kontrol eder; satın alınmış içerik kütüphane tarafında erişilebilir kalır.

## Endpoint'ler
- `POST /auth/register`
  - JSON body: `{ "name": "...", "email": "...", "password": "...", "phone": "..." }`
  - Kullanıcıyı oluşturur, aktivasyon maili gönderir ve giriş yaptırmaz.
  - Yanıt: `{ ok, requiresEmailVerification, email, message }`
- `POST /auth/login`
  - JSON body: `{ "email": "...", "password": "..." }`
  - Hesap onaylanmamışsa `403 EMAIL_NOT_VERIFIED` döner.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/social-login`
  - JSON body: `{ "email": "...", "provider": "google|apple", "name": "...", "phone": "..." }`
  - Kullanıcı varsa JWT döner, yoksa `404 USER_NOT_FOUND`.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/social-register`
  - JSON body: `{ "email": "...", "name": "...", "provider": "google|apple", "phone": "..." }`
  - Sosyal sağlayıcı ile ilk kayıt olan kullanıcıyı oluşturur, hesabı doğrulanmış kabul eder ve JWT döner.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/guest-token`
  - Body zorunlu değildir.
  - CDN kısa ömürlü bir `guest` JWT üretir.
  - Bu token yalnızca Hasura'da `guest` rolüne verdiğiniz public izinler kadar erişim sağlamalıdır.
  - Yanıt: `{ ok, user, token, expiresAt }`
- `GET /home/bootstrap`
  - Anasayfa bootstrap verisini direkt Postgres'ten toplu döner.
  - Yanıt: `{ ok, cache, data: { sliders, magazines, books, newspapers, attachments, homeBookEntries, homeMagazineEntries } }`
  - Hata durumunda `503` ve `{ ok, error, code, requestId, details }` döner.
- `GET /home/sliders`
- `GET /home/magazines`
- `GET /home/books`
- `GET /home/newspapers`
- `GET /home/attachments`
- `GET /home/showcase/books`
- `GET /home/showcase/magazines`
  - Anasayfa fallback yüklemeleri için section bazlı endpointlerdir.
  - Hepsi direkt Postgres'ten okunur ve `{ ok, cache, data: [...] }` döner.
  - Hata durumunda `requestId` ile birlikte daha açıklayıcı `code/details` alanları döner ve sunucu `app_error_logs` tablosuna da kayıt düşmeye çalışır.
- `GET /app/feature-flags?id=1|2`
  - Mobil uygulamanın sürüme göre gazete/dergi görünürlüğünü belirleyen `app_feature_flags` kaydını direkt Postgres'ten döner.
  - `id=1` Android, `id=2` iOS için kullanılır.
  - Yanıt: `{ ok, cache, data: { id, version, hide_magazines, hide_newspapers } | null }`
  - Hata durumunda `503` ve `{ ok, error, code, requestId, details }` döner; sunucu ayrıca `app_error_logs` tablosuna kayıt düşmeye çalışır.
- `GET /auth/me`
  - Auth: `Authorization: Bearer <JWT>`
  - Oturumdaki kullanıcının güvenli profil özetini döner.
- `GET /auth/me/access`
  - Auth: `Authorization: Bearer <JWT>`
  - Query: `itemType` opsiyoneldir. (`book`, `magazine`, `magazine_issue`, `newspaper_subscription`, `ek`)
  - Oturumdaki kullanıcının aktif erişim kayıtlarını direkt Postgres'ten döner.
- `GET /auth/me/orders`
  - Auth: `Authorization: Bearer <JWT>`
  - Query: `includeItems=true` verilirse sipariş kalemlerini de ekler.
  - Oturumdaki kullanıcının sipariş geçmişini direkt Postgres'ten döner.
- `GET /auth/me/orders/:id`
  - Auth: `Authorization: Bearer <JWT>`
  - Oturumdaki kullanıcıya ait tek sipariş detayını ve kalemlerini direkt Postgres'ten döner.
- `PATCH /auth/me`
  - Auth: `Authorization: Bearer <JWT>`
  - JSON body: `{ "name": "...", "phone": "..." }`
  - Kullanıcının ad/telefon bilgilerini günceller.
- `PUT /auth/me/avatar`
  - Auth: `Authorization: Bearer <JWT>`
  - JSON body: `{ "avatarUrl": "https://yeniasya.b-cdn.net/profil/public/..." }`
  - Kullanıcının profil fotoğrafını günceller.
- `DELETE /auth/me/avatar`
  - Auth: `Authorization: Bearer <JWT>`
  - Kullanıcının profil fotoğrafını kaldırır.
- `POST /auth/email-verification/request`
  - JSON body: `{ "email": "..." }`
  - Güvenlik için kullanıcı kayıtlı olsun ya da olmasın aynı başarılı yanıtı döner.
  - Aktivasyon bağlantısını `EMAIL_VERIFICATION_WEB_URL` adresine üretir.
- `POST /auth/email-verification/confirm`
  - JSON body: `{ "token": "..." }`
  - Token tek kullanımlıktır; başarılı işlemden sonra aynı kullanıcıya ait açık tokenlar kapatılır ve kullanıcı doğrulanır.
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
  - Aktif `user_content_access.newspaper_subscription` veya `manual_newspaper_users` erişimi olan kullanıcı için seçilen tarihin görüntüleme URL'ini döner.
  - Tarih `newspaper` tablosunda varsa sistemdeki `file_url` kullanılır.
  - Tarih sistemde yoksa CDN içindeki legacy PDF proxy URL'i döner.
  - Yanıt: `{ ok, date, url, isPrivate, source }`
- `GET /newspaper/legacy-file?date=YYYY-MM-DD`
  - Auth: `Authorization: Bearer <JWT>`
  - Aktif e-gazete aboneliği olan kullanıcı için eski sistemdeki PDF'i CDN üzerinden proxy eder.
- `POST /graphql`
  - Hasura proxy (JWT zorunlu).
  - Header: `Authorization: Bearer <JWT>`
  - JSON body: `{ "query": "...", "variables": { ... }, "operationName": "..." }`
- `POST /upload/public`  
  - Form-data alanları: `file` (foto/pdf), `type` (kitap|gazete|dergi|ek|slider|profil).  
  - Dosya yolları: `storage/<type>/public/`.
  - Auth: `Authorization: Bearer <JWT>`.
- `POST /upload/private`  
  - Form-data: `file` ve `type` (kitap|gazete|dergi|ek).  
  - Dosya yolu: `storage/<type>/private/`.  
  - Yanıt `url` değeri: `/private/<type>/<filename>`.
  - Auth: `Authorization: Bearer <JWT>`.
- `POST /upload/delete`
  - Auth: `Authorization: Bearer <JWT>` (admin rol).
  - JSON body: `{ "url": "https://yeniasya.b-cdn.net/kitap/private/..." }` veya `{ "path": "/kitap/private/..." }`
  - Sadece yönetilen CDN/Bunny path'lerini siler. Eski asset cleanup akışları için kullanılır.
- `GET /public/:type/:filename`  
  - Direkt erişim, auth yok.
- `GET /private/:type/:filename`  
  - Auth: `Authorization: Bearer <JWT>` veya `x-api-key: <AUTH_TOKEN>`.
- `POST /private/view`  
  - JSON body: `{"path": "/private/<type>/<file.pdf>"}` (pdf uzantısı zorunlu).  
  - Auth: `Authorization: Bearer <JWT>` veya `x-api-key: <AUTH_TOKEN>`.  
  - PDF inline açılır, cache kapalı, frame-ancestors ALLOWED_FRAME_ANCESTORS ile kontrol edilir.
- `POST /private/view-file`
  - JSON body: `{"path": "/private/<type>/<file.pdf>"}` (pdf uzantısı zorunlu).
  - Auth: `Authorization: Bearer <JWT>` veya `x-api-key: <AUTH_TOKEN>`.
  - Ham PDF byte stream döner; web istemcisi için fallback endpoint olarak kullanılabilir.
- `GET /private/view-file`
  - Auth: `Authorization: Bearer <JWT>` veya `x-api-key: <AUTH_TOKEN>`.
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
- CORS: `.env` içinde `ALLOWED_ORIGINS` (örn. `http://localhost:3000,https://cdn.yeniasyadijital.com`) ve `ALLOWED_HEADERS` (varsayılan `content-type,x-api-key,authorization,x-mail-token`).
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
