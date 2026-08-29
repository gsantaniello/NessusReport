# NessusReport

NessusReport converte uno o più report Nessus v2 (`.nessus`) in:

- un CSV UTF-8 delimitato da `|`, adatto all’analisi tabellare;
- un report Word (`.docx`) con riepilogo delle severity e finding raggruppati.

La versione 1.0.0 è una riscrittura per Python 3 del prototipo 0.3.2. L’elaborazione avviene interamente in locale: lo strumento non effettua scansioni e non invia dati a servizi esterni.

> **Stato:** versione modernizzata e verificata con dati simulati. Prima dell’uso operativo è consigliato validarla con copie anonimizzate di report Nessus reali.

## Miglioramenti rispetto alla versione 0.3.2

- supporto a Python 3.10 e versioni successive;
- interfaccia CLI con `--help`, `--version` e logging;
- parsing XML incrementale con DTD, entità esterne e accesso di rete disabilitati;
- deduplicazione deterministica;
- severità `Info`, `Low`, `Medium`, `High` e `Critical` correttamente distinte;
- supporto ai principali campi CVSS v2 e v3;
- CSV generato con il modulo standard `csv`, quoting e UTF-8 con BOM;
- DOCX generato con `python-docx`, senza costruire WordprocessingML tramite concatenazione di stringhe;
- raggruppamento dello stesso plugin su più asset;
- scrittura atomica degli output e validazione dell’archivio DOCX;
- test automatici e dataset Nessus simulato;
- template riproducibile tramite `tools/build_template.py`.

## Requisiti

- Python 3.10 o successivo;
- `lxml`;
- `python-docx`.

Non è necessario alcun eseguibile precompilato.

## Installazione

Creare un ambiente virtuale:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Su Windows, l’attivazione dell’ambiente è normalmente:

```powershell
.venv\Scripts\Activate.ps1
```

In alternativa è possibile installare le sole dipendenze:

```bash
python -m pip install -r requirements.txt
```

## Utilizzo

Dopo l’installazione:

```bash
nessus-report scansione.nessus --output report
```

Senza installare il comando:

```bash
python nessus_report.py scansione.nessus \
  --template Nessus_Report_Template.docx \
  --output report
```

Il comando produce:

```text
report.csv
report.docx
```

### Più report Nessus

```bash
nessus-report scansione_dmz.nessus scansione_lan.nessus --output report_completo
```

Per compatibilità con il vecchio script è supportato anche un elenco separato da virgole:

```bash
nessus-report scansione_dmz.nessus,scansione_lan.nessus --output report_completo
```

### Solo CSV o solo Word

```bash
nessus-report scansione.nessus --output report --csv-only
nessus-report scansione.nessus --output report --docx-only
```

### Guida completa

```bash
nessus-report --help
```

## Template Word

Il nuovo template si chiama:

```text
Nessus_Report_Template.docx
```

Contiene stili, margini, header, footer e numerazione delle pagine. Il contenuto del report viene aggiunto dal programma.

Il template può essere rigenerato in modo deterministico:

```bash
python tools/build_template.py Nessus_Report_Template.docx
```

## Test con dati simulati

Il file `samples/sample_scan.nessus` contiene esclusivamente dati fittizi e indirizzi riservati alla documentazione (`192.0.2.0/24`). Include:

- 2 asset simulati;
- 5 istanze di finding;
- 4 finding raggruppati;
- 1 Critical;
- 2 Medium;
- 1 Low;
- 1 Info.

Esecuzione del test dimostrativo:

```bash
python nessus_report.py samples/sample_scan.nessus \
  --template Nessus_Report_Template.docx \
  --output sample_report \
  --verbose
```

Output atteso:

```text
Processed 5 findings across 2 assets (Critical=1, High=0, Medium=2, Low=1, Info=1).
```

## Test automatici

```bash
python -m unittest discover -s tests -v
```

La suite verifica:

- parsing del report simulato;
- conteggi e ordinamento delle severity;
- raggruppamento multi-host;
- generazione e rilettura del CSV;
- validità dell’archivio DOCX e presenza dei contenuti attesi;
- rifiuto di XML con DTD o dichiarazioni di entità.

## Struttura del CSV

Il CSV contiene una riga per ogni istanza rilevata e include:

- host, IP, FQDN, sistema operativo e asset name;
- porta, protocollo e servizio;
- severity numerica e descrittiva;
- plugin ID, titolo, famiglia e risk factor;
- punteggi e vettori CVSS v2/v3;
- CVE;
- descrizione, mitigazione ed evidenza tecnica.

Il delimitatore è `|`. I valori contenenti delimitatori o ritorni a capo vengono quotati secondo le regole CSV.

## Struttura del report Word

Il DOCX comprende:

1. metadati di generazione;
2. numero di asset e finding;
3. riepilogo cromatico per severity;
4. schede ordinate dalla severity più alta alla più bassa;
5. raggruppamento degli asset interessati dallo stesso plugin;
6. synopsis, descrizione, remediation ed evidenze per ciascun asset.

## Sicurezza e privacy

I report Nessus possono contenere informazioni riservate, inclusi indirizzi, versioni software, configurazioni e output tecnici. Usare lo strumento in locale e proteggere input e output secondo le regole dell’organizzazione.

Il parser rifiuta DTD ed entità XML e non consente accesso di rete durante il parsing. Queste misure non sostituiscono la validazione degli input e l’esecuzione in un ambiente con privilegi minimi.

## Limitazioni attuali

- la versione 1.0.0 è stata verificata su un dataset simulato, non su tutte le varianti prodotte dalle diverse versioni di Nessus e Tenable Security Center;
- finding con strutture XML non standard potrebbero richiedere adattamenti;
- i report con evidenze molto lunghe possono produrre schede su più pagine;
- il formato CSV è intenzionalmente pipe-delimited per compatibilità con il flusso storico.

## Migrazione dalla versione 0.3.2

Vecchio comando:

```text
python nessusreport_v0.3.2.py input.nessus Template_CV.docx output
```

Nuovo comando:

```text
python nessus_report.py input.nessus --template Nessus_Report_Template.docx --output output
```

La versione 1.0.0 non dipende dal vecchio `.exe` e non richiede Python 2.
