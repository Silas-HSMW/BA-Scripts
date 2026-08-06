## R Studio code zur Datenanalyse und Plot-Erstellung
### Voraussetzungen

Die Anwendung benötigt entweder:

die rohen korrelierten TCP-Flow-JSON-Daten. In diesem Fall muss zunächst der Codeblock „0. Alle Daten zu CSV zusammenfügen“ ausgeführt werden. Hierfür ist der Quellpfad entsprechend anzupassen.
oder die bereits erzeugte CSV-Datei aus dem Ordner Daten dieses Repositories (nach dem Entpacken).

Wird die bereitgestellte CSV-Datei verwendet, kann der Codeblock „0. Alle Daten zu CSV zusammenfügen“ übersprungen werden.

Vor dem Ausführen des Codes muss R installiert und eingerichtet sein. Zusätzlich müssen die folgenden Bibliotheken installiert werden:


### Ungefilterter Datensatz

Aus Gründen der Einfachheit wird derselbe Code sowohl für balancierte/gefilterte als auch für unbalancierte/ungefilterte Datensätze verwendet.

Hierfür müssen die im Code mit „Hinweis“ gekennzeichneten Stellen entsprechend angepasst werden. Je nach Auswertung sind auskommentierte Codezeilen ein- bzw. auszukommentieren oder boolesche Parameter (z. B. balance) anzupassen.

Die jeweils erforderlichen Änderungen sind direkt in den entsprechenden Codeblöcken dokumentiert.
