# File API (Node.js)

Fotoğraf ve PDF yükleyebileceğiniz, public ve private alanları olan minimal API.

## Kurulum
1) Node 18+ kurulu olmalı.  
2) Ortam değişkenlerini ayarla:
```bash
cp .env.example .env
# AUTH_TOKEN, VIEW_TOKEN_SECRET, HASURA_ENDPOINT, HASURA_ADMIN_SECRET, JWT_SECRET zorunlu
# Origin yetkisi için ALLOWED_ORIGINS'i kendi domainlerinle doldur (virgülle ayır)
# Base64 viewer kapalıdır (istersen ENABLE_BASE64_VIEWER=true)
# İsteğe bağlı: MAX_BASE64_VIEW_BYTES=5242880
# JWT opsiyonelleri:
# JWT_EXPIRES_IN=1d
# JWT_ISSUER=yeniasya
# JWT_AUDIENCE=yeniasya-app
# JWT_DEFAULT_ROLE=user
# JWT_ALLOWED_ROLES=user
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

## Endpoint'ler
- `POST /auth/register`
  - JSON body: `{ "name": "...", "email": "...", "password": "...", "phone": "..." }`
  - Yanıt: `{ ok, user, token, expiresAt }`
- `POST /auth/login`
  - JSON body: `{ "email": "...", "password": "..." }`
  - Yanıt: `{ ok, user, token, expiresAt }`
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
- `GET /health` durumu kontrol eder.

## Kurallar
- İzin verilen MIME: `application/pdf`, `image/jpeg`, `image/png`, `image/webp`.
- 50MB üstü dosyalar reddedilir.
- Private dosyalar `storage/<type>/private` dizinlerine yazılır.
- CORS: `.env` içinde `ALLOWED_ORIGINS` (örn. `http://localhost:3000,https://cdn.yeniasyadigital.com`) ve `ALLOWED_HEADERS` (varsayılan `content-type,x-api-key,authorization`).
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
