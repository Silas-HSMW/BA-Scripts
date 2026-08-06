# Übersicht des Bachelor-Repository zu "Möglichkeiten und Grenzen des TLS-Fingerprinting in der Analyse serverseitig erhobener Netzwerkkommunikation"

### Verwendete Versionen
*Python Version:*
python 3.14

*R Version:* 
R 4.6.1

(Versionen der Verwendeten Biblioteken sind den jeweiligen unterordnern zu untnehmen)

## Übersicht Ordnerstruktur:

### AlternativePlots
Enthält die Alternativen Plotdarstellungen für unterschiedliche Seeds

### R
Enthält den R-Code für die Datenaufbereitung und Analyse/Auswertung

### ServerconfigNginx
Enthält Ressourcen und Konfigurationen des Nginx Servers

### ServerconfigApache
Enthält Ressourcen und Konfigurationen des Apache Servers

### createData
Enthält die Scripts zum Erzeugen der Rohdaten (Linux)

### createData_win
Enthält die Scripts zum Erzeugen der Rohdaten (Windows)

### data
Enthält den Vollständig aufbereiteten Datensatz


### dataset
Das hier enthaltene Script wurde zur Erstellung des Datensatzes verwendet (Datenkorrelation)

### Workflow
Server Einrichten -> Daten Erstellen mit "createData" erstellen -> "dataset" nutzen um Rodaten im ersten schritt aufzuarbeiten -> R Skript nutzen um daten vollständig aufzuarbeiten und Daten zu analysieren
