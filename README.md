# AI Phishing Email Investigator

AI Phishing Email Investigator adalah aplikasi web untuk membantu pengguna menganalisis email yang dicurigai sebagai phishing. Aplikasi mengirimkan data email yang diberikan pengguna ke Google Gemini melalui backend, lalu menampilkan laporan investigasi terstruktur dengan indikator, penilaian risiko, tingkat keyakinan, keterbatasan investigasi, dan rekomendasi.

## Tujuan dan fungsi utama

Aplikasi ini membantu pengguna:

- mengidentifikasi indikator phishing dan rekayasa sosial;
- meninjau identitas pengirim, struktur URL, header email, serta hasil SPF, DKIM, dan DMARC jika data tersebut diberikan;
- membedakan observasi terkonfirmasi, indikator mencurigakan, dan asumsi yang belum terverifikasi;
- memahami penilaian risiko dan keyakinan secara terpisah; dan
- menyimpan serta membuka kembali riwayat investigasi di browser.

Hasil analisis adalah penilaian berbasis AI terhadap informasi yang dikirimkan pengguna, bukan keputusan final tentang apakah email pasti berbahaya atau sah.

## Fitur utama

- Dashboard statistik investigasi.
- Form investigasi dengan validasi input.
- Analisis AI melalui Google Gemini API.
- Laporan investigasi terstruktur 12 bagian.
- Penilaian risiko `LOW`, `MEDIUM`, `HIGH`, atau `CRITICAL` serta keyakinan `LOW`, `MEDIUM`, atau `HIGH`.
- Analisis sender, social engineering, URL/domain, header, dan autentikasi email berdasarkan data yang tersedia.
- Riwayat di `localStorage` dengan aksi lihat, hapus, dan hapus semua.
- Terjemahan laporan antara Bahasa Indonesia dan English, dengan cache terjemahan di browser.
- Health indicator untuk status konfigurasi API.
- Light mode dan dark mode.

## Teknologi

- Frontend: HTML5, CSS3, dan Vanilla JavaScript.
- Backend: Node.js dan Express.js.
- AI: Google Gemini API menggunakan package `@google/genai` dan method `models.generateContent`.
- Konfigurasi: `dotenv` untuk memuat variabel dari `.env`.
- Middleware: Express JSON/url-encoded parser.
- Penyimpanan riwayat dan cache terjemahan: `localStorage` browser.

## Alur kerja dan arsitektur

```text
Browser
  public/index.html + public/style.css + public/script.js
        │ HTTP JSON
        ▼
Node.js/Express (server.js)
  validasi dan sanitasi input
  memuat prompts/system-prompt.md
  memanggil @google/genai
        │ HTTPS melalui SDK
        ▼
Google Gemini API
        │ JSON terstruktur
        ▼
Browser menampilkan laporan dan menyimpan riwayat di localStorage
```

Frontend tidak memanggil Gemini secara langsung. API key hanya dibaca oleh backend dari environment variable.

## Persyaratan sistem

- Node.js 18 atau lebih baru.
- npm.
- Google Gemini API key.
- Browser modern yang mendukung `localStorage`, Fetch API, dan JavaScript modern.

## Instalasi dan konfigurasi

1. Install dependency:

   ```bash
   npm install
   ```

2. Buat file `.env` di root project. Contoh:

   ```env
   GEMINI_API_KEY=your-gemini-api-key-here
   GEMINI_MODEL=gemini-3.5-flash
   PORT=3000
   ```

   `GEMINI_API_KEY` wajib diisi. `GEMINI_MODEL` dan `PORT` bersifat opsional; nilai default masing-masing adalah `gemini-3.5-flash` dan `3000`.

3. Dapatkan API key melalui [Google AI Studio](https://aistudio.google.com/app/apikey). Jangan memasukkan API key asli ke source code, frontend, repository, atau dokumentasi.

## Menjalankan aplikasi

Jalankan server:

```bash
npm start
```

Buka `http://localhost:3000` di browser. Script `start` dan `dev` pada `package.json` sama-sama menjalankan `node server.js`.

Tanpa `GEMINI_API_KEY`, halaman frontend dan riwayat lokal tetap dapat dibuka, tetapi analisis dan terjemahan yang membutuhkan Gemini tidak tersedia.

## Endpoint API

### `POST /api/analyze`

Menganalisis email menggunakan Gemini.

Request JSON:

```json
{
  "senderName": "Security Team",
  "senderEmail": "security@example.com",
  "subject": "Urgent: Account suspended",
  "emailBody": "Email body text",
  "url": "https://example.com/login",
  "rawHeaders": "From: ...\\nReply-To: ...",
  "spfResult": "FAIL",
  "dkimResult": "NONE",
  "dmarcResult": "FAIL",
  "language": "en"
}
```

`senderName`, `senderEmail`, `subject`, dan `emailBody` wajib. Field lain opsional. `language` menerima `id` atau `en`.

Response sukses berbentuk `{ "success": true, "result": { ... } }`. `result` berisi field laporan seperti `executiveSummary`, `emailInfo`, `suspiciousIndicators`, `riskLevel`, `confidenceLevel`, `riskExplanation`, `recommendedActions`, dan `investigationLimitations`.

Response error berbentuk `{ "error": "...", "type": "..." }`, dengan tipe seperti `VALIDATION_ERROR`, `CONFIG_ERROR`, `AUTH_ERROR`, `RATE_LIMIT`, `TIMEOUT`, `SERVICE_ERROR`, atau `INVALID_RESPONSE`.

### `POST /api/translate`

Menerjemahkan laporan yang sudah ada. Endpoint ini tidak menjalankan ulang analisis phishing.

Request JSON:

```json
{
  "language": "id",
  "result": {
    "executiveSummary": "Existing report result"
  }
}
```

`result` harus berupa object laporan lengkap dan `language` harus `id` atau `en`. Response sukses berbentuk `{ "success": true, "result": { ... } }`. Struktur laporan, enum risiko/keyakinan, alamat email, domain, URL, dan nilai teknis tertentu dipertahankan oleh validasi backend.

### `GET /api/health`

Memeriksa status server dan apakah `GEMINI_API_KEY` tersedia. Contoh response:

```json
{
  "status": "ok",
  "apiConfigured": true,
  "provider": "Google Gemini",
  "model": "gemini-3.5-flash",
  "timestamp": "2026-11-25T00:00:00.000Z"
}
```

## Struktur direktori

```text
.
├── public/
│   ├── index.html       # Markup Dashboard, Investigasi, Riwayat, dan Tentang
│   ├── script.js        # Navigasi, i18n, analisis, terjemahan, rendering, dan localStorage
│   └── style.css        # Gaya UI, responsive layout, dan light/dark mode
├── prompts/
│   └── system-prompt.md # Aturan investigasi dan format keluaran AI
├── server.js            # Server Express, validasi, endpoint API, dan integrasi Gemini
├── package.json         # Script dan dependency Node.js
├── package-lock.json    # Lockfile dependency
└── README.md            # Dokumentasi project
```

## Batasan sistem

- Analisis hanya menggunakan informasi yang diberikan pengguna dan bersifat probabilistik.
- Aplikasi tidak melakukan verifikasi real-time terhadap reputasi domain, DNS, URL, redirect, sertifikat TLS, respons HTTP, atau isi website.
- URL hanya dianalisis secara struktural dan tidak dibuka, dikunjungi, atau dieksekusi oleh aplikasi.
- SPF, DKIM, dan DMARC hanya dianalisis jika hasilnya diberikan pengguna; aplikasi tidak melakukan pemeriksaan autentikasi independen.
- Ketepatan laporan bergantung pada kelengkapan dan keakuratan data email.
- Riwayat dan cache terjemahan berada di `localStorage`, sehingga bersifat lokal pada browser/perangkat dan dapat hilang jika storage dibersihkan.
- Analisis dan terjemahan memerlukan konfigurasi Gemini API yang valid, koneksi jaringan, serta kuota layanan yang tersedia.

## Keamanan dan penggunaan API key

- Simpan `GEMINI_API_KEY` hanya di `.env` pada server.
- Jangan commit `.env`, membagikan API key, atau menaruhnya di `public/`.
- Backend membatasi body request hingga 50 KB, memvalidasi field, membatasi panjang input, dan menghapus null byte sebelum memproses data.
- URL kiriman pengguna tidak dibuka atau di-resolve.
- Frontend melakukan escaping pada nilai laporan saat dirender ke HTML.
- Riwayat email disimpan di browser pengguna; jangan masukkan data sensitif jika kebijakan organisasi tidak mengizinkannya.

## Catatan implementasi

`prompts/system-prompt.md` mengatur analisis berbasis bukti, atribusi sumber temuan ke field email, pemisahan risk dan confidence, serta format JSON laporan. Dokumentasi ini tidak menyatakan adanya verifikasi eksternal yang tidak dilakukan oleh aplikasi.
