# Kartlarım (Card Holder)

Bank kartları, şəxsiyyət sənədləri və gizli qeydlər üçün şəxsi PWA.

## Təhlükəsizlik
- Məlumat yalnız telefonda (IndexedDB) saxlanılır, heç bir serverə göndərilmir.
- Hər element ayrıca **AES-256-GCM** ilə şifrələnir; açar ana şifrədən **PBKDF2-SHA256 (600 000 təkrar)** ilə alınır.
- Ana şifrə heç yerdə saxlanılmır — unudulsa, bərpa yoxdur.
- Avtomatik kilid, 5 səhv cəhddən sonra gözləmə, kopyalanan məlumat 45 san. sonra buferdən silinir.

## Lokal işə salmaq
```bash
python3 -m http.server 8787
```
Sonra `http://localhost:8787` açın.

## Telefona quraşdırmaq
Service worker HTTPS tələb edir, ona görə faylları istənilən statik hostinqə yükləyin
(GitHub Pages, Netlify, Cloudflare Pages). Sonra telefonda saytı açın:
- **iPhone (Safari):** Paylaş → "Ana ekrana əlavə et"
- **Android (Chrome):** ⋮ → "Tətbiqi quraşdır"

## Yeniləmə
Faylları dəyişəndə `sw.js`-dəki `VERSION`-u artırın ki, telefon yeni versiyanı yükləsin.

## Ehtiyat nüsxə
Ayarlar → "Şifrəli nüsxəni çıxar". Fayl şifrəlidir; telefonu dəyişəndə ilk ekranda
"Ehtiyat nüsxədən bərpa et" ilə geri yükləyin.
