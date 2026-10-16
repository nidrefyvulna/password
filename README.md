# Password Generator & Reverse

Web statis (HTML, CSS, JavaScript) untuk membuat password dari sebuah teks,
lalu membalikkannya lagi menjadi teks asli. Semua proses berjalan di
browser Anda. Tidak ada data yang dikirim atau disimpan.

## Fitur

- **Generate Password**: teks (A) + panjang (B) + seed (C) + karakter (X)
  menjadi password (D).
- **Reverse Password**: password (D) + panjang (B) + seed (C) + karakter (X)
  kembali menjadi teks asli (A).
- Pilih karakter lewat centang (a-z, A-Z, 0-9, simbol) dan/atau tulis
  sendiri.
- Tombol **Copy** untuk menyalin hasil.

## Cara pakai

### Generate Password

1. Di halaman awal, klik **Generate Password**.
2. Isi **Teks / String (A)**: teks yang ingin diubah menjadi password
   (maksimal 99 byte; untuk huruf biasa 1 karakter = 1 byte).
3. Isi **Panjang password (B)**: panjang total password. Lihat petunjuk
   **Minimal: ...** di sebelah label; B tidak boleh lebih kecil dari itu.
4. Isi **Seed (C)**: angka bulat (maksimal 16 digit). Makin panjang dan
   acak, makin sulit ditebak.
5. Pilih **karakter yang dipakai (X)** dengan mencentang grup dan/atau
   mengetik karakter custom. Password hanya akan berisi karakter ini.
6. Klik **Generate**. Hasil muncul di bawahnya. Klik **Copy** untuk
   menyalin.

### Reverse Password

1. Di halaman awal, klik **Reverse Password**.
2. Tempel **Password (D)**.
3. Isi **Panjang password (B)**: sama dengan panjang password tadi.
4. Isi **Seed (C)** dan pilih **karakter (X)**: harus SAMA PERSIS dengan
   saat Generate.
5. Klik **Reverse**. Teks asli muncul di bawahnya. Klik **Copy** untuk
   menyalin.

## Aturan penting

1. **Simpan B, C, dan pengaturan karakter.** Reverse hanya berhasil bila
   password, panjang, seed, dan karakter sama persis dengan saat Generate.
2. **Ada panjang minimal.** Karena password harus bisa dibalik, ia tidak
   bisa lebih pendek dari batas tertentu. Teks lebih panjang atau karakter
   lebih sedikit membuat minimalnya lebih besar. Web menghitungnya
   otomatis.
3. **Angka di awal dan akhir password** adalah panjang teks asli (dalam
   byte), dipakai oleh Reverse.
   - Jika karakter 0-9 dipilih lengkap, tampil sebagai angka 2 digit
     (contoh `08`).
   - Jika tidak, panjang ditulis dengan karakter yang Anda pilih, supaya
     password tetap hanya berisi karakter pilihan Anda.
4. **Karakter custom** ditambahkan ke grup yang dicentang. Untuk memakai
   karakter custom saja, hilangkan semua centang. Urutan mengetik tidak
   berpengaruh, dan karakter ganda diabaikan.
5. Karakter custom hanya boleh ASCII yang bisa dicetak, tanpa spasi.

## Contoh

Generate dengan centang a-z, A-Z, 0-9:

| Input              | Nilai          |
| ------------------ | -------------- |
| Teks (A)           | `Hello123`     |
| Panjang (B)        | `24`           |
| Seed (C)           | `12345`        |
| Hasil Password (D) | `089H0fNQuWtte227MpRpLh08` |

Reverse dengan password di atas, B = 24, seed 12345, dan centang yang
sama menghasilkan `Hello123`.

Contoh karakter custom saja (tanpa centang), custom `aAbBcCdD123@#`:

| Input              | Nilai          |
| ------------------ | -------------- |
| Teks (A)           | `rahasia-saya` |
| Panjang (B)        | `40`           |
| Seed (C)           | `987654321`    |
| Hasil Password (D) | `#dDA@cdAc1b1bB3aAa3b3A@cd3DDbb1ad1#ba##d` |

Di sini angka panjang (12) ditulis dengan karakter custom, yaitu `#d` di
awal dan di akhir.

## Pesan error yang umum

| Pesan                                         | Penyebab dan solusi |
| --------------------------------------------- | ------------------- |
| Panjang password (B) terlalu pendek           | Naikkan B sampai angka minimal yang ditampilkan. |
| Panjang password yang ditempel ..., tetapi B = ... | B harus sama dengan panjang password. |
| Karakter ... tidak ada di set karakter        | Pilih karakter yang sama dengan saat Generate. |
| Angka panjang di awal dan akhir tidak valid   | Password tidak lengkap/berubah, atau karakter berbeda. |
| Gagal membaca password                        | Seed, panjang, atau karakter berbeda dari saat Generate. |

## Batasan

- Teks (A): 1 sampai 99 byte. Panjang password (B): 1 sampai 1024.
- Seed (C): bilangan bulat, 0 sampai 16 digit.
- Minimal 2 karakter berbeda di set karakter.

## Keamanan

Alat ini **bukan enkripsi standar**. Ia menyamarkan teks menjadi password
yang bisa dibalik, tetapi tidak setara AES atau standar kriptografi
lainnya.

- Jangan dipakai untuk melindungi data penting.
- Seed pendek (mis. `123`) mudah ditebak. Gunakan seed 10 digit atau lebih.
- Angka panjang di awal dan akhir password terlihat jelas.
- Siapa pun yang tahu teks, panjang, seed, dan karakter bisa membuat ulang
  password yang sama. Siapa pun yang tahu password, panjang, seed, dan
  karakter bisa membaca teks aslinya. Rahasiakan semuanya.

## Struktur proyek

```
PasswordGeneratorAndReverse/
  index.html   struktur halaman
  style.css    tampilan
  script.js    logika dan penghubung UI
  README.md    dokumen ini
```

`made with help of AI`
