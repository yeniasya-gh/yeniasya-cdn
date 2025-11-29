# File API (Node.js)

Fotoğraf ve PDF yükleyebileceğiniz, public ve private alanları olan minimal API.

## Kurulum
1) Node 18+ kurulu olmalı.  
2) Ortam değişkenlerini ayarla:
```bash
cp .env.example .env
# AUTH_TOKEN'ı değiştir
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
- `POST /upload/public`  
  - Form-data alanları: `file` (foto/pdf), `type` (kitap|gazete|dergi).  
  - Dosya yolları: `storage/<type>/public/`.
- `POST /upload/private`  
  - Form-data: `file` ve `type=kitap` zorunlu.  
  - Dosya yolu: `storage/kitap/private/`.  
  - Yanıt `url` değeri: `/private/<filename>`.
- `GET /public/:type/:filename`  
  - Direkt erişim, auth yok.
- `GET /private/:filename`  
  - Header: `x-api-key: <AUTH_TOKEN>` veya `Authorization: Bearer <AUTH_TOKEN>`.
- `GET /health` durumu kontrol eder.

## Kurallar
- İzin verilen MIME: `application/pdf`, `image/jpeg`, `image/png`, `image/webp`.
- 20MB üstü dosyalar reddedilir.
- Private dosyalar yalnızca `kitap` tipinde tutulur (`storage/kitap/private`).

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
