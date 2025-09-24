# 📜 NSE Scripts Kullanım Kılavuzu

## 🔍 NSE Scripts Nedir?

NSE (Nmap Scripting Engine), Nmap'in en güçlü özelliklerinden biridir. Lua programlama dili ile yazılmış scriptler kullanarak ağ taramalarınızı daha detaylı ve kapsamlı hale getirebilirsiniz.

## 🎯 NSE Scripts'in Avantajları

- **Detaylı Servis Tespiti**: Sadece port açık/kapalı değil, servislerin detaylı bilgilerini alır
- **Güvenlik Açığı Tespiti**: Bilinen güvenlik açıklarını otomatik olarak tespit eder
- **Banner Grabbing**: Servislerin banner bilgilerini toplar
- **SSL/TLS Analizi**: Sertifika bilgilerini ve güvenlik ayarlarını kontrol eder
- **HTTP Servis Analizi**: Web servislerinin detaylı analizini yapar

## 🚀 Temel Kullanım

### 1. **Varsayılan Scripts**
Eğer hiçbir script belirtmezseniz, uygulama otomatik olarak şu scriptleri kullanır:
```
banner,http-title,ssl-cert,ssh-hostkey
```

### 2. **Tek Script Kullanımı**
```
banner
```

### 3. **Birden Fazla Script**
Virgülle ayırarak birden fazla script kullanabilirsiniz:
```
banner,http-title,ssl-cert
```

### 4. **Script Kategorileri**
Kategori adı kullanarak tüm o kategorideki scriptleri çalıştırabilirsiniz:
```
vuln
safe
auth
```

## 📋 Popüler NSE Scripts

### **🔐 Güvenlik Scripts**
| Script | Açıklama | Kullanım |
|--------|----------|----------|
| `vuln` | Güvenlik açığı taraması | `vuln` |
| `exploit` | Exploit tespiti | `exploit` |
| `malware` | Malware tespiti | `malware` |
| `intrusive` | Agresif güvenlik testleri | `intrusive` |

### **🌐 HTTP/Web Scripts**
| Script | Açıklama | Kullanım |
|--------|----------|----------|
| `http-title` | Web sayfası başlığı | `http-title` |
| `http-headers` | HTTP başlıkları | `http-headers` |
| `http-methods` | Desteklenen HTTP metodları | `http-methods` |
| `http-enum` | Web dizin ve dosya taraması | `http-enum` |
| `http-sql-injection` | SQL injection testi | `http-sql-injection` |

### **🔒 SSL/TLS Scripts**
| Script | Açıklama | Kullanım |
|--------|----------|----------|
| `ssl-cert` | SSL sertifika bilgileri | `ssl-cert` |
| `ssl-enum-ciphers` | Desteklenen şifreleme algoritmaları | `ssl-enum-ciphers` |
| `ssl-heartbleed` | Heartbleed açığı testi | `ssl-heartbleed` |
| `ssl-poodle` | POODLE açığı testi | `ssl-poodle` |

### **🔑 Kimlik Doğrulama Scripts**
| Script | Açıklama | Kullanım |
|--------|----------|----------|
| `ssh-hostkey` | SSH anahtar bilgileri | `ssh-hostkey` |
| `ssh-auth-methods` | SSH kimlik doğrulama yöntemleri | `ssh-auth-methods` |
| `ftp-anon` | Anonim FTP erişimi | `ftp-anon` |
| `smb-enum-shares` | SMB paylaşımları | `smb-enum-shares` |

### **📊 Bilgi Toplama Scripts**
| Script | Açıklama | Kullanım |
|--------|----------|----------|
| `banner` | Servis banner bilgileri | `banner` |
| `version` | Servis versiyon bilgileri | `version` |
| `dns-zone-transfer` | DNS zone transfer testi | `dns-zone-transfer` |
| `snmp-info` | SNMP bilgileri | `snmp-info` |

## 🎯 Kullanım Senaryoları

### **1. Web Servisi Taraması**
```
http-title,http-headers,http-methods,ssl-cert
```

### **2. Güvenlik Açığı Taraması**
```
vuln,exploit,ssl-heartbleed,ssl-poodle
```

### **3. SSH Servisi Analizi**
```
ssh-hostkey,ssh-auth-methods,banner
```

### **4. Kapsamlı Tarama**
```
banner,http-title,ssl-cert,ssh-hostkey,vuln
```

### **5. Hızlı Bilgi Toplama**
```
banner,version,http-title
```

## ⚠️ Önemli Notlar

### **Güvenlik Uyarıları**
- `vuln` ve `exploit` scriptleri agresif olabilir
- Hedef sistemlerde log kayıtları bırakabilir
- Sadece kendi sistemlerinizde veya izin aldığınız sistemlerde kullanın

### **Performans**
- Çok fazla script kullanmak taramayı yavaşlatabilir
- `intrusive` scriptleri özellikle yavaştır
- Hedef sistemin yanıt süresine göre timeout ayarlayın

### **Hata Durumları**
- Bazı scriptler belirli servisler için çalışmayabilir
- Script hataları genellikle taramayı durdurmaz
- Hata mesajları log dosyalarında görülebilir

## 🔧 Gelişmiş Kullanım

### **Script Parametreleri**
Bazı scriptler parametre alabilir:
```
http-enum --script-args http-enum.basepath=/
```

### **Script Kategorileri**
- `safe`: Güvenli scriptler (varsayılan)
- `intrusive`: Agresif scriptler
- `vuln`: Güvenlik açığı scriptleri
- `exploit`: Exploit scriptleri
- `malware`: Malware tespit scriptleri
- `discovery`: Keşif scriptleri
- `auth`: Kimlik doğrulama scriptleri

### **Özel Script Kombinasyonları**
```
# Web güvenlik taraması
http-title,http-headers,http-sql-injection,ssl-cert,ssl-enum-ciphers

# SSH güvenlik taraması
ssh-hostkey,ssh-auth-methods,ssh-brute

# Veritabanı taraması
mysql-info,postgresql-brute,mssql-info

# Ağ servisleri taraması
smb-enum-shares,ftp-anon,telnet-encryption
```

## 📝 Örnek Kullanımlar

### **1. Basit Web Taraması**
```
http-title,http-headers,ssl-cert
```

### **2. Güvenlik Odaklı Tarama**
```
vuln,ssl-heartbleed,ssl-poodle,http-sql-injection
```

### **3. Servis Keşfi**
```
banner,version,http-title,ssh-hostkey
```

### **4. Kapsamlı Güvenlik Taraması**
```
vuln,exploit,malware,ssl-cert,http-enum
```

## 🎯 İpuçları

1. **Başlangıç**: Önce `banner,http-title,ssl-cert` ile başlayın
2. **Güvenlik**: `vuln` scriptlerini dikkatli kullanın
3. **Performans**: Çok fazla script kullanmayın
4. **Hedef**: Hedef sistemin türüne göre script seçin
5. **Test**: Önce kendi sisteminizde test edin

## 📚 Kaynaklar

- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [NSE Script Database](https://nmap.org/nsedoc/)
- [NSE Script Examples](https://nmap.org/nsedoc/scripts/)

---

**⚠️ Uyarı**: Bu scriptleri sadece kendi sistemlerinizde veya açık izin aldığınız sistemlerde kullanın. Yetkisiz sistem taraması yasal sorunlara yol açabilir.
