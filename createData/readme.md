Diese Scripts wurden zum Erstellen und Dokumentieren der Automatisierten Anfragen erstellt
### Versionen
Dumpcap (Wireshark) 4.7.2.

**Python Bibliotheken:**
- selenium        4.45.0
- requests        2.34.2
- urllib3         2.7.0
- (alle weiteren imports stammen aus der Python Standardbibliothek)

**Anwendungen**
*Anmerkungen: Versionen der Anwendungen Variieren basierend auf dem Client und Betriebssystem auf dem sie ausgeführt wurden. Gleichzeitig wurden updates installiert um mögliche "natürliche tls-Stack veränderungen" aufzunehmen. Daher Verändern sich auch die Versionen. Genaue versionen Sind im Datensatz Dokumentiert. Es würde mit den folgenden Versionen durchgeführt:*

Curl:

"curl 8.19.0 (Windows) libcurl/8.19.0 Schannel zlib/1.3.1 WinIDN WinLDAP"  
"curl 8.21.0 (x86_64-pc-linux-gnu) libcurl/8.21.0 OpenSSL/3.6.3 zlib/1.3.2 brotli/1.2.0 zstd/1.5.7 libidn2/2.3.8 libpsl/0.21.5 libssh2/1.11.1 nghttp2/1.69.0 ngtcp2/1.24.0 nghttp3/1.17.0 mit-krb5/1.22.2"         
"curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 zlib/1.3 brotli/1.1.0 zstd/1.5.5 libidn2/2.3.7 libpsl/0.21.2 (+libidn2/2.3.7) libssh/0.10.6/openssl/zlib nghttp2/1.59.0 librtmp/2.3 OpenLDAP/2.6.10"
"curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP"

Requests:

- "requests 2.34.2 / python 3.14.6"                                                     
- "requests 2.32.5 / python 3.9.10"
- "requests 2.34.2 / python 3.12.3"

Firefox:

- "Mozilla Firefox 152.0.5"                                                                                                                                                                                          
- "Mozilla Firefox 152.0.4"                                                                                                                                                                                          
- "Mozilla Firefox 152.0.6"  

Chromium:

- "Chromium 150.0.7871.114 Arch Linux"                                                                                                                                                                               
- "Chromium 150.0.7871.46 Arch Linux"
- "Chromium 150.0.7871.124 Arch Linux"
- "Chromium 149.0.7827.200 for Linux Mint"                                                                                                                                                                           
- "Chromium 150.0.7871.46 for Linux Mint"

Chrome:

- "Google Chrome 150.0.7871.114 Desktop"
- "Google Chrome 150.0.7871.115 Desktop"

### Anwendung
#### Browser_Chrome.py
1. Bibliotheken installieren
`pip install selenium`
2. Wireshark installieren (für dumpcap)
3. Firefox Installieren (der Pfad sollte automatisch erkannt werden, ansonsten in FIREFOX_BINARY manuell festlegen)

#### Browser_Firefox.py
1. Bibliotheken installieren
`pip install selenium`
2. Wireshark installieren (für dumpcap)
3. Chromium Installieren (der Pfad sollte automatisch erkannt werden, ansonsten in CHROME_BINARY

#### Curl.py
1. Curl dürfte standardmäßig installiert sein und imports sind nur aus Standardbibliothek. Es funktioniert also "out of the box"
#### custom_requests.py
1. Bibliotheken installieren
`pip install requests urllib3`
#### Control_poc.py
1. CLIENT_ID entsprechend festlegen (eindeutiger Name)
2. Server mit Namen, Port, IPs und Endpunkten festlegen
