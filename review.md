# Review (fokus: keamanan & robustness koneksi jaringan, correctness output CLI)

## Ringkasan singkat
- Output human-readable rusak karena literal string korup; kode tidak akan terkompilasi dalam kondisi saat ini.
- Operasi jaringan (TLS, DNS) belum memakai context/deadline yang konsisten sehingga riskan hang di host yang tidak responsif.
- Penanganan error banyak yang ditelan sehingga diagnosa sulit dan hasil bisa menyesatkan.
- Ada code smell minor (variabel tak terpakai, fallback protokol terbatas) yang menurunkan maintainability.

## Daftar temuan detail
- [Critical] stackscanner.go:534 printHuman  
  - Penjelasan: Literal string korup (karakter “dY…” dengan kutip ganda berserakan) memecah sintaks sehingga fungsi tidak bisa dikompilasi; sekalipun dikompilasi, output tidak terbaca.  
  - Saran perbaikan: Ganti dengan string ASCII biasa dan separator yang jelas, misalnya `fmt.Printf("=== Scan Result for: %s\n", info.URL)` dan hilangkan karakter non-ASCII yang tidak perlu.

- [Major] stackscanner.go:440 checkTLS  
  - Penjelasan: `tls.Dial` dipanggil tanpa context/dialer timeout; koneksi TCP 443 yang ditahan firewall bisa menggantung lama sebelum timeout OS. Error juga tidak diteruskan ke caller sehingga TLSValid=false tanpa alasan yang jelas.  
  - Saran perbaikan: Gunakan `net.Dialer{Timeout: 5 * time.Second}` + `tls.DialWithDialer` atau `tls.Dialer.DialContext`, propagasikan error dan log detail saat verbose.

- [Major] stackscanner.go:409 dnsLookup  
  - Penjelasan: Semua error DNS diabaikan (`LookupCNAME`, `LookupIP`, `LookupAddr`), sehingga kegagalan resolusi tidak diketahui dan hasil bisa kosong tanpa sebab. Selain itu tidak ada batas waktu (context) sehingga resolusi bisa blok lama.  
  - Saran perbaikan: Pasang context dengan timeout, tangkap error dan log saat verbose, dan kembalikan error ke caller jika resolusi gagal total.

- [Major] stackscanner.go:379 fetch  
  - Penjelasan: HTTP client tidak memakai context sehingga tidak bisa dibatalkan lebih awal; hanya timeout hard 15s. Pada target lambat, seluruh scan akan menunggu penuh tanpa opsi cancel/timeout granular.  
  - Saran perbaikan: Terima `context.Context` di `scan`/`fetch`, buat request dengan `NewRequestWithContext`, dan gunakan shared `http.Client` dengan transport yang sudah di-tune (Dialer timeout, TLS handshake timeout, IdleConnTimeout).

- [Minor] stackscanner.go:167 applyRules  
  - Penjelasan: Map `categories` dan `names` dibuat tetapi tidak dipakai; dead code ini mengurangi keterbacaan.  
  - Saran perbaikan: Hapus variabel tak terpakai atau manfaatkan untuk melampirkan ID/nama ke hasil bila diperlukan.

- [Minor] stackscanner.go:371 normalizeURL  
  - Penjelasan: Otomatis memaksa https tanpa fallback ke http; target yang hanya melayani http akan gagal langsung.  
  - Saran perbaikan: Coba https dulu, jika gagal (mis. connection refused), fallback ke http atau beri opsi flag untuk memilih protokol.

## Saran refactor & idiomatic Go
```go
// Contoh pemakaian context + timeout untuk HTTP dan TLS.
func fetch(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	return client.Do(req)
}

func checkTLS(ctx context.Context, host string) (bool, string, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{ServerName: host})
	if err != nil {
		return false, "", err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return true, "", nil
	}
	return true, state.PeerCertificates[0].Issuer.CommonName, nil
}

func printHuman(info *TechStack) {
	fmt.Printf("=== Scan Result for: %s\n", info.URL)
	if info.URL != info.FinalURL && info.FinalURL != "" {
		fmt.Printf("    Final URL: %s\n", info.FinalURL)
	}
	fmt.Println(strings.Repeat("=", 60))
	// ...lanjutkan dengan label ASCII yang jelas...
}
```

## Checklist
- Penanganan error konsisten: Perlu perbaikan
- Penggunaan context pada operasi I/O, HTTP, dan database: Perlu perbaikan
- Potensi deadlock, race condition, dan kebocoran goroutine: Perlu perbaikan (risiko hang karena ketiadaan timeout)
- Validasi input & sanitasi data: Perlu perbaikan
- Struktur paket & pemisahan responsibility: Perlu perbaikan
- Penggunaan log (level, konteks, dan pesan): Perlu perbaikan
