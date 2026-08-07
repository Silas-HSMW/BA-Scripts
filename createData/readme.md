Diese Scripts wurden zum Erstellen und Dokumentieren der Automatisierten Anfragen erstellt
### Versionen
Dumpcap (Wireshark) 4.7.2.
**Python Bibliotheken:**
selenium        4.45.0
requests        2.34.2
urllib3         2.7.0
(alle weiteren imports stammen aus der Python Standardbibliothek)
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
