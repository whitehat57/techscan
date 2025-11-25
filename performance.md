# Performance Review (asumsi konteks: CLI web tech scanner, beban: single target per eksekusi, ukuran HTML bisa besar)

## Ringkasan singkat
- Sudah menggunakan satu `http.Client` dengan transport tuned; ini baik untuk re-use koneksi.
- Pembacaan HTML dan normalisasi huruf kecil membuat beberapa salinan string besar; risiko memori tinggi pada halaman besar.
- Tidak ada batching/concurrency; throughput untuk banyak target akan linear dan lambat.
- I/O jaringan sudah diberi timeout, tapi belum ada limit baca body sehingga bisa menyedot memori jika target mengirim respons besar.

## Daftar bottleneck / isu performa
- [Major] stackscanner.go:296–301 `io.ReadAll` + `strings.ToLower(string(bodyBytes))`  
  - Masalah: Membuat 2+ salinan buffer besar (raw bytes → string → lower string); pada halaman MBs ini menaikkan memory/GC.  
  - Saran: Batasi ukuran yang dibaca (mis. `io.LimitReader` 1–2MB), gunakan satu string saja, dan lakukan normalisasi per pencarian (atau gunakan `bytes.ToLower` pada buffer sekali lalu pakai untuk parsing tanpa salinan tambahan jika goquery masih bisa memakai buffer yang sama).

- [Major] stackscanner.go:217–238 `matchSignal` untuk `script_src`, `header_key`, `ip` melakukan scanning linear per kategori.  
  - Masalah: Untuk rules atau halaman dengan banyak script/headers, lookup berulang tanpa indeks.  
  - Saran: Bangun map/set sekali (mis. map lowercased header keys/values, set script src) untuk O(1) contains; preallocate slice hasil dengan kapasitas `len(rules.Technologies)` untuk mengurangi re-allocation.

- [Major] stackscanner.go:282–318 `scan` memproses satu target secara sinkron.  
  - Masalah: Untuk banyak target, throughput bottleneck di single-threaded scan; tidak ada worker pool atau concurrency control.  
  - Saran: Jika ada daftar target, gunakan worker pool dengan rate limit; buat `Scan(ctx, target string, ...)` dieksekusi oleh worker dan share HTTP/DNS client.

- [Minor] stackscanner.go:399 `extractScriptSrcs`  
  - Masalah: Slice `srcs` tanpa prealloc; setiap append bisa reallocate jika banyak script tags.  
  - Saran: Prealloc dengan `make([]string, 0, doc.Find("script").Length())`.

- [Minor] stackscanner.go:518–559 `hashFavicon` membaca seluruh body ke memori.  
  - Masalah: Jika favicon besar/abusif, tetap di-alloc.  
  - Saran: Batasi ukuran favicon (mis. 1MB) dengan `io.LimitReader`, atau abort jika `Content-Length` > batas.

## Contoh snippet perbaikan
```go
// before -> after (kurangi copy & limit body)
// before
bodyBytes, _ := io.ReadAll(resp.Body)
htmlLower := strings.ToLower(string(bodyBytes))

// after
const maxBody = 2 << 20 // 2MB safeguard
limited := io.LimitReader(resp.Body, maxBody)
bodyBytes, _ := io.ReadAll(limited)
bodyStr := string(bodyBytes)             // satu salinan
lowerBody := strings.ToLower(bodyStr)    // hanya jika wajib; bisa ditunda per match

// before -> after (prealloc script src)
// before
var srcs []string
doc.Find("script").Each(func(_ int, s *goquery.Selection) { ... })

// after
scriptCount := doc.Find("script").Length()
srcs := make([]string, 0, scriptCount)
doc.Find("script").Each(func(_ int, s *goquery.Selection) { ... })

// before -> after (worker pool untuk banyak target)
// before: sequential scan(target)
// after (sketsa)
type job struct{ url string }
workers := 8
jobs := make(chan job, workers)
var wg sync.WaitGroup
for i := 0; i < workers; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for j := range jobs {
            scan(ctx, j.url, verbose, rules) // share httpClient
        }
    }()
}
```

## Checklist performa
- Pola HTTP client sudah efisien (re-use, timeout, transport): OK
- Penggunaan database/redis/kafka (jika ada) sudah memperhatikan connection pool dan batching: OK (tidak ada)
|- Tidak ada goroutine leak yang jelas: OK (selama single target; perlu desain saat ditambah concurrency)
- Tidak ada loop besar yang melakukan I/O sinkron berulang tanpa batching/buffering: Perlu perbaikan (sequential untuk multi-target)
- Penggunaan `context.Context` di operasi berat sudah konsisten: OK (HTTP/TLS/DNS sudah)
- Data struktur utama (slice/map) sudah di-preallocate bila size diketahui: Perlu perbaikan

## Saran profiling & benchmarking
- Benchmark: buat `BenchmarkScanSmallPage` dan `BenchmarkScanLargePage` dengan HTTP test server lokal (serve HTML kecil/besar) untuk mengukur latency/alloc/op.
- Profiling: gunakan `pprof` (heap, allocs) saat memproses halaman besar untuk melihat dampak copy HTML dan lowercasing; profil CPU saat rules banyak untuk melihat hotspot `matchSignal`.
- Metrik penting: latency per scan, throughput (scan/s) untuk daftar target, alloc/op dan total bytes allocated, peak heap, jumlah goroutine saat menjalankan batch.
