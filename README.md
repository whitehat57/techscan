# techscan

**Project Overview**
- **techscan**: tool ringan untuk fingerprinting teknologi situs web (CMS, frontend, backend, analytics, CDN, hosting, fingerprint, dan kategori lain) berbasis rule-based signatures, dengan opsi deep probing dan integrasi Cloudflare Radar URL Scanner.

**What it does**
- Mengambil halaman target, mengekstrak header, HTML, script `src`, melakukan lookup DNS (A, CNAME, rDNS), memeriksa TLS, serta menghitung hash `favicon.ico` (SHA1, MD5, MurmurHash3).
- Opsional `--deep`: probing path populer (robots.txt, sitemap.xml, wp-json, wp-login, wp-admin, plus random 404) dan merekam status/body sample sebagai sinyal.
- Opsional `--radar`: mengirim URL ke Cloudflare Radar URL Scanner (butuh kredensial) dan memetakan hasil Wappalyzer ke kategori scanner; hasil mentah disimpan ke folder `cloudflare/`.
- Mencocokkan hasil ekstraksi terhadap `rules.json` untuk mendeteksi teknologi berdasarkan sinyal (signals).

**Contents**
- **`stackscannerv2.go`**: kode sumber utama scanner.
- **`rules.json`**: file konfigurasi rule; bebas menambah kategori atau sinyal baru.
- **`build.sh`**: helper script untuk membangun binary.
- **`cloudflare/`**: output mentah Cloudflare Radar (dibuat saat flag `--radar` dipakai).

**Requirements**
- **Go**: direkomendasikan `Go 1.20+` (berjalan di `1.18+`).
- Koneksi jaringan untuk HTTP/DNS/TLS.
- Untuk `--radar`: env var `CF_RADAR_ACCOUNT_ID` dan `CF_API_TOKEN`.

**Quick Setup**
- Inisialisasi modul Go (jika belum ada `go.mod`):

```bash
cd /path/to/techscan
go mod init github.com/whitehat57/techscan
go mod tidy
```

**Build**
- Menggunakan helper `build.sh` (direkomendasikan):

```bash
./build.sh                # build ke ./bin/stackscanner
./build.sh -o ./release/stackscanner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ./build.sh -o ./bin/stackscanner-linux
```

- Atau langsung dengan `go build`:

```bash
go build -o ./bin/stackscanner .
```

**Usage**
- Basic (skema otomatis dipaksa ke `https://` bila tidak disebut):

```bash
./bin/stackscanner <target>
# contoh:
./bin/stackscanner example.com
```

- Flags:
  - `-v` : verbose (log debug ke stderr)
  - `-json` : output JSON (lebih cocok untuk pipeline)
  - `-rules <path>` : jalur file rules JSON (default: `rules.json`)
  - `--deep` : aktifkan probing path tambahan + random 404 (membuka sinyal `probe_status` dan `probe_body`)
  - `--radar` : pakai Cloudflare Radar URL Scanner (butuh `CF_RADAR_ACCOUNT_ID` dan `CF_API_TOKEN`)
  - `--cookie "k=v;..."` : set header `Cookie` untuk seluruh request (utama, favicon, probe)

Contoh lengkap:

```bash
./bin/stackscanner -v -json --deep --radar -rules ./rules.json --cookie "sess=123" https://example.com
```

Output JSON berisi struktur `TechStack` dengan field seperti `url`, `final_url`, `headers`, `tls_valid`, `tls_issuer`, `ips`, `cname`, `reverse_dns`, `favicon_sha1`, `favicon_mmh3`, `favicon_md5`, `cms`, `frontend`, `backend`, `analytics`, `cdn`, `hosting`, `fingerprints`, serta `other_categories` (untuk kategori tambahan). Hasil Radar, jika dipakai, otomatis digabung ke kategori yang sama dan file mentahnya disimpan di `cloudflare/<host>_<uuid>_<timestamp>.json`.

**Format `rules.json` (ringkasan)**
- File JSON berisi object dengan key `technologies` (array). Setiap item memiliki struktur berikut:

- **Contoh ringkas**:

```json
{
	"technologies": [
		{
			"id": "wordpress",
			"name": "WordPress",
			"category": "cms",
			"threshold": 1,
			"signals": [
				{ "source": "html", "type": "contains", "value": "wp-content", "weight": 1 },
				{ "source": "header", "key": "x-powered-by", "type": "contains", "value": "wordpress", "weight": 2 }
			]
		}
	]
}
```

- **Field penting**:
	- `id`: identifier unik teknologi.
	- `name`: nama yang akan ditampilkan.
	- `category`: kategori deteksi (mis. `cms`, `frontend`, `backend`, `analytics`, `cdn`, `hosting`, `fingerprint`, dll.).
	- `threshold`: skor minimal untuk menganggap teknologi terdeteksi (default `1` jika tidak di-set).
	- `signals`: daftar sinyal (lihat di bawah).

- **Signal fields**:
	- `source`: sumber sinyal. Nilai yang didukung oleh scanner:
		- `html` (konten HTML utuh)
		- `header` (value header spesifik; gunakan `key` untuk nama header)
		- `header_key` (cari pola pada nama header)
		- `script_src` (nilai `src` dari tag `<script>`)
		- `dns_cname` (isi CNAME)
		- `dns_rdns` (hasil reverse DNS PTR)
		- `ip` (alamat IP)
		- `favicon_sha1` (SHA1 dari `favicon.ico`)
		- `favicon_mmh3` (MurmurHash3 uint32 dari favicon)
		- `favicon_md5` (MD5 dari `favicon.ico`)
		- `probe_status` (kombinasi path + status HTTP dari probing `--deep`, contoh: `/wp-login.php:200`)
		- `probe_body` (cuplikan body lowercased dari probing `--deep`)
	- `type`: jenis pencocokan: `contains`, `equals`, `prefix`.
	- `key`: (opsional) untuk `header` (mis. `X-Powered-By`).
	- `value`: pola yang dicocokkan.
	- `weight`: bobot sinyal (default `1`).

Catatan:
- Scanner menormalisasi string target (lowercase + trim) sebelum mencocokkan.
- Sinyal `probe_status`/`probe_body` hanya tersedia ketika flag `--deep` diaktifkan.
- Jika `threshold`/`weight` tidak diisi, otomatis diset ke `1`.

**Contoh penggunaan praktis**

- Human-readable output:

```bash
./bin/stackscanner -v https://example.com
```

- Simpan ke JSON:

```bash
./bin/stackscanner -json -rules ./rules.json example.com > result.json
```

- Gabungkan deteksi lokal dengan Cloudflare Radar:

```bash
CF_RADAR_ACCOUNT_ID=xxx CF_API_TOKEN=yyy ./bin/stackscanner --radar example.com
```

**Troubleshooting & Tips**
- Jika dependency Go belum diunduh: `go mod tidy`.
- Jika fetch gagal, cek koneksi, akses target, atau user-agent; sesuaikan di `stackscannerv2.go` jika diperlukan.
- TLS handshake bisa gagal jika host tidak melayani 443; akan tercatat `tls_valid=false`.
- Tambah signature baru di `rules.json` dan atur `threshold`/`weight` sesuai kebutuhan.
- `--radar` membutuhkan env var valid; tanpa itu akan gagal di awal pemanggilan.
- Gunakan `--cookie` bila target perlu sesi/login agar aset (script/favicon) muncul.

**Contributing**
- Perbaikan rule, tambahan fitur, dan laporan bug sangat disambut. Silakan fork dan buka PR.

**License**
- Proprietary – All rights reserved. Lihat `LICENSE` untuk ketentuan lengkap.
