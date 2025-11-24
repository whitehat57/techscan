# techscan

**Project Overview**
- **techscan**: sebuah tool ringan untuk mendeteksi teknologi yang dipakai sebuah situs web (CMS, frontend, backend, analytics, CDN, hosting, fingerprint, dan lain-lain) berdasarkan rule-based signatures.

**What it does**
- Mengambil halaman target, mengekstrak header, HTML, script `src`, melakukan lookup DNS (A, CNAME, rDNS), memeriksa TLS, dan meng-hash `favicon.ico`.
- Mencocokkan hasil ekstraksi terhadap sebuah kumpulan `rules.json` untuk mendeteksi teknologi berdasarkan sinyal (signals).

**Contents**
- **`stackscanner.go`**: kode sumber utama scanner.
- **`rules.json`**: file konfigurasi rule (tidak disertakan jika tidak ada) yang berisi definisi teknologi dan sinyalnya.
- **`build.sh`**: helper script untuk membangun binary (dibuat oleh skrip bantuan).

**Requirements**
- **Go**: versi modern (direkomendasikan `Go 1.20+`, bekerja pada `1.18+`).
- Koneksi jaringan saat menjalankan scanner (melakukan fetch HTTP(s), DNS lookup, TLS handshake).

**Quick Setup**
- Inisialisasi modul Go (jika belum ada `go.mod`):

```bash
cd /path/to/techscan
go mod init github.com/whitehat57/techscan
go mod tidy
```

Perintah `go mod tidy` akan mengunduh dependensi yang diperlukan seperti `github.com/PuerkitoBio/goquery` dan `github.com/spaolacci/murmur3`.

**Build**
- Ada dua cara untuk membangun binary:

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
- Basic:

```bash
./bin/stackscanner <target>
# contoh:
./bin/stackscanner example.com
```

- Flags:
- `-v` : verbose (mencetak log debug ke stderr)
- `-json` : output dalam format JSON (cocok untuk pemrosesan otomatis)
- `-rules <path>` : jalur ke file rules JSON (default: `rules.json`)

Contoh lengkap:

```bash
./bin/stackscanner -v -json -rules ./rules.json https://example.com
```

Output JSON akan berisi struktur `TechStack` yang mengandung informasi seperti `url`, `final_url`, `headers`, `tls_valid`, `ips`, `cname`, `reverse_dns`, `favicon_sha1`, `cms`, `frontend`, `backend`, dll.

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
	- `category`: kategori deteksi (contoh: `cms`, `frontend`, `backend`, `analytics`, `cdn`, `hosting`, `fingerprint`, dll.).
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
	- `type`: jenis pencocokan: `contains`, `equals`, `prefix`.
	- `key`: (opsional) untuk `header` (mis. `X-Powered-By`).
	- `value`: pola yang dicocokkan.
	- `weight`: bobot sinyal (default `1`).

Catatan: scanner menormalisasi target string (lowercase + trim) sebelum mencocokkan.

**Contoh penggunaan praktis**

- Mendeteksi dan menampilkan hasil secara human-readable:

```bash
./bin/stackscanner -v https://example.com
```

- Menyimpan hasil JSON:

```bash
./bin/stackscanner -json -rules ./rules.json example.com > result.json
```

**Troubleshooting & Tips**
- Jika binary tidak berjalan karena dependency Go belum diunduh: jalankan `go mod tidy`.
- Jika fetch halaman gagal, cek koneksi jaringan, akses target, dan apakah target memblokir user-agent. Anda dapat menyesuaikan user-agent di kode `stackscanner.go` jika diperlukan.
- TLS handshake mungkin gagal jika host tidak melayani di port 443 atau server menolak koneksi; itu dianggap `tls_valid=false`.
- Jika ingin menambahkan signature baru, edit `rules.json` dan atur `threshold`/`weight` sesuai kebutuhan.

**Contributing**
- Perbaikan rule, tambahan fitur, dan laporan bug sangat disambut. Silakan fork dan buka PR.

**License**
- Lihat `LICENSE` di repository untuk detail lisensi.
