# Generatore di report Nessus in formato Word e CSV

## 1. Scopo

Lo script converte uno o più file di esportazione Nessus (`.nessus`) in due report:

- un documento Microsoft Word (`.docx`) con una scheda riepilogativa per vulnerabilità;
- un file di testo delimitato (`.csv`) contenente il dettaglio delle vulnerabilità rilevate.

Lo script **non esegue scansioni di sicurezza** e non si collega ai sistemi analizzati. Opera esclusivamente sui file locali forniti in ingresso.

> **Stato del progetto:** il codice è stato scritto per una versione datata di Python, verosimilmente Python 2.7. Prima dell'uso in produzione deve essere aggiornato e collaudato con Python 3.

## 2. Flusso di elaborazione

L'elaborazione avviene in quattro fasi:

1. lettura dei report XML Nessus;
2. estrazione delle informazioni sugli host e sulle vulnerabilità;
3. generazione del contenuto principale del documento Word;
4. generazione del file CSV.

Per limitare il consumo di memoria durante la lettura XML, lo script utilizza `lxml.etree.iterparse`. I risultati estratti vengono comunque conservati in memoria fino al termine dell'elaborazione.

## 3. Requisiti

### Dipendenze software

- Python 2.7, per l'esecuzione del codice originale;
- libreria Python `lxml`;
- un file `.docx` valido da utilizzare come contenitore/modello;
- uno o più report Nessus in formato `.nessus`.

La dipendenza non standard può essere installata, in un ambiente Python compatibile, con:

```bash
pip install lxml
```

### Compatibilità con Python 3

Il codice originale non è direttamente compatibile con Python 3. Tra gli interventi necessari:

- sostituire `cgi.escape`, non più disponibile, con `html.escape`;
- correggere la scrittura del CSV, che attualmente passa byte a un file aperto in modalità testo;
- sostituire la deduplicazione basata su `sorted(vulns)`, non valida per liste di dizionari;
- gestire esplicitamente encoding, eccezioni e validazione degli input.

## 4. Sintassi

```bash
python script.py <input_nessus> <modello_docx> <nome_output> [modalità]
```

### Parametri

| Posizione | Parametro | Obbligatorio | Descrizione |
|---:|---|:---:|---|
| 1 | `input_nessus` | Sì | Percorso di un file `.nessus` oppure elenco di percorsi separati da virgole. |
| 2 | `modello_docx` | Sì | Documento Word valido usato come contenitore per il report. |
| 3 | `nome_output` | Sì | Percorso e nome base dei file prodotti, senza estensione. |
| 4 | `modalità` | No | `1` attiva una modalità alternativa, ma la relativa implementazione è commentata e non funzionante. Omettere il parametro. |

### Esempio con una scansione

```bash
python script.py scansione.nessus modello.docx report_cliente
```

### Esempio con più scansioni

```bash
python script.py scansione_dmz.nessus,scansione_lan.nessus modello.docx report_completo
```

Lo script genera nella directory indicata:

```text
report_completo.docx
report_completo.csv
```

I nomi contenenti spazi devono essere racchiusi tra virgolette secondo le regole della shell utilizzata.

## 5. File di ingresso

### Report Nessus

Il file `.nessus` è un documento XML prodotto da Tenable Nessus. Per ogni elemento `ReportHost`, lo script acquisisce i dati dell'host e analizza gli elementi `ReportItem` associati.

Informazioni host estratte:

- nome del target;
- indirizzo IP;
- FQDN;
- nome NetBIOS;
- sistema operativo;
- indirizzo MAC.

Informazioni sulle vulnerabilità estratte, quando disponibili:

- ID e nome del plugin Nessus;
- famiglia e tipo del plugin;
- porta, protocollo e servizio;
- severity e risk factor;
- synopsis, descrizione, soluzione e plugin output;
- punteggi e vettori CVSS v2 e CVSS v3;
- punteggi e vettori temporali CVSS;
- disponibilità di exploit;
- riferimenti CVE, BID, OSVDB e cross-reference.

I campi assenti vengono normalmente sostituiti con una stringa vuota, `None`, `n/a` oppure un testo predefinito, a seconda del punto del programma.

### Modello Word

Il secondo argomento deve essere un archivio `.docx` valido. Un file Word moderno è infatti un archivio ZIP contenente documenti XML e altre risorse.

Lo script copia tutte le parti del modello, ma **sostituisce completamente** il file interno `word/document.xml` con XML costruito nel codice. Di conseguenza:

- il contenuto principale del modello non viene conservato;
- stili, temi e altre risorse possono essere riutilizzati solo se compatibili con l'XML generato;
- intestazioni, piè di pagina o immagini esterne a `word/document.xml` possono rimanere nell'archivio;
- il parametro `document` ricevuto da `generate_docx_by_vulns()` non viene utilizzato.

## 6. File prodotti

### Report CSV

Il file usa il carattere pipe (`|`) come delimitatore, non la virgola. L'intestazione contiene i seguenti campi:

| Campo | Contenuto |
|---|---|
| `IP` | Indirizzo IP dell'host. |
| `Target` | Nome del target nel report Nessus. |
| `FQDN` | Fully Qualified Domain Name. |
| `Asset Name` | Nome NetBIOS dell'host. |
| `Asset Operating System` | Sistema operativo rilevato. |
| `Port` | Porta e protocollo nel formato `porta/PROTOCOLLO`. |
| `Service` | Nome del servizio, convertito in maiuscolo. |
| `Severity` | Valore numerico Nessus originale. |
| `Mitigation Priority` | Contenuto del campo Nessus `risk_factor`. |
| `Vulnerability Title` | Nome del plugin Nessus. |
| `CVSS2 Base Score` | Punteggio CVSS v2, con virgola decimale. |
| `Attack Vector (AV)` | Vettore d'attacco ricavato dal CVSS v2. |
| `CVSS2 Vector` | Vettore CVSS v2. |
| `CVSS2 Temporal Score` | Punteggio temporale CVSS v2. |
| `CVSS2 Temporal Vector` | Vettore temporale CVSS v2. |
| `CVSS3 Base Score` | Punteggio CVSS v3, con virgola decimale. |
| `CVSS3 Vector` | Vettore CVSS v3 senza il prefisso iniziale. |
| `CVSS3 Temporal Score` | Punteggio temporale CVSS v3. |
| `CVSS3 Temporal Vector` | Vettore temporale CVSS v3. |
| `Description` | Descrizione della vulnerabilità. |
| `Mitigation` | Soluzione proposta dal plugin. |
| `Output` | Evidenza tecnica prodotta dal plugin. |

Nel campo `Output`, ritorni a capo e caratteri `|` vengono sostituiti con spazi. La stessa protezione non viene applicata sistematicamente a tutti gli altri campi.

### Report Word

Il documento Word presenta una tabella per ciascun plugin Nessus rilevato. Le occorrenze dello stesso plugin vengono raggruppate e la tabella riporta l'elenco dei target interessati.

Le vulnerabilità sono ordinate per severity, dalla più alta alla più bassa, limitatamente ai livelli inclusi dal ciclo di generazione. La tabella contiene principalmente:

- servizio, porta e protocollo;
- titolo, synopsis e descrizione;
- severity con colore associato;
- punteggio CVSS v2;
- target coinvolti;
- soluzione consigliata;
- output tecnico;
- livello di competenza dedotto dalla metrica CVSS v2 `AC`.

Mappatura cromatica definita nel codice:

| Severity | Etichetta Word | Colore |
|---:|---|---|
| 4 | High | Rosso |
| 3 | High | Rosso |
| 2 | Medium | Arancione |
| 1 | Low | Azzurro |
| 0 | Info | Verde, ma il livello non viene incluso dal ciclo corrente |

## 7. Funzioni principali

### `parseNessusXML(xmlFile)`

Analizza incrementalmente il report Nessus e restituisce una lista di dizionari, uno per ogni `ReportItem`. A ogni vulnerabilità aggiunge i dati dell'host corrente e aggrega i riferimenti CVE, OSVDB, BID e XREF.

### `strip_multiple_spaces(s)`

Sostituisce sequenze di almeno due spazi con un singolo spazio. Viene utilizzata nella preparazione delle descrizioni inserite nel report Word.

### `generate_csv(vulns)`

Costruisce in memoria l'intero contenuto del CSV. Normalizza alcuni ritorni a capo, estrae informazioni dal vettore CVSS e restituisce una singola stringa pronta per essere scritta su disco.

### `generate_docx_by_vulns(document, vulns)`

Genera direttamente l'XML WordprocessingML del documento. Raggruppa le vulnerabilità per `pluginID`, raccoglie i target coinvolti e sostituisce i segnaposto `VALUE00`-`VALUE22` presenti nella tabella XML incorporata nel codice.

### `main(argv=None)`

Valida il numero minimo degli argomenti, legge i report Nessus, apre il modello Word, genera i file `.docx` e `.csv` e chiude gli archivi ZIP.

## 8. Gestione delle severity

Nel formato Nessus, i valori normalmente utilizzati sono:

| Valore | Significato abituale |
|---:|---|
| 0 | Info |
| 1 | Low |
| 2 | Medium |
| 3 | High |
| 4 | Critical |

Nel codice corrente ci sono due anomalie:

1. il ciclo `range(1, 5)` genera soltanto i livelli `4`, `3`, `2` e `1`, escludendo gli elementi informativi;
2. il livello `4` viene mostrato come `High`, anziché `Critical`, e usa lo stesso colore del livello `3`.

Il CSV conserva invece il valore numerico originale della severity.

## 9. Limitazioni e problemi noti

### Affidabilità

- L'uso esteso di `except:` senza indicare il tipo di errore nasconde problemi di input e difetti di programmazione.
- Se gli argomenti sono insufficienti, lo script stampa soltanto `Input Error!` senza mostrare la sintassi corretta.
- Gli errori durante la creazione del CSV vengono ignorati.
- Non viene verificata l'esistenza dei file, la loro estensione o la validità del contenuto XML/ZIP.
- Un errore durante l'elaborazione può lasciare file incompleti o archivi non chiusi correttamente.

### Correttezza dei dati

- Il tentativo di eliminare duplicati tramite `groupby(sorted(vulns))` è fragile in Python 2 e non funziona in Python 3.
- Le liste dei target sono costruite a partire da `set`, quindi il loro ordine non è stabile.
- I riferimenti OSVDB vengono estratti ma non aggiunti alla stringa finale `reference`.
- Nel CSV alcuni campi potrebbero contenere il delimitatore `|` e alterare il numero delle colonne.
- I decimali vengono convertiti da punto a virgola solamente in alcuni campi.
- L'interpretazione del vettore CVSS v2 dipende rigidamente dalla posizione delle metriche.

### Scalabilità

- Tutte le vulnerabilità e l'intero CSV vengono mantenuti in memoria.
- La generazione Word esegue più cicli annidati sull'insieme delle vulnerabilità e dei plugin.
- L'XML della tabella Word è incorporato come una stringa molto estesa, difficile da mantenere.

### Sicurezza

- Il parser XML non configura esplicitamente opzioni difensive per input non affidabili.
- I percorsi di input e output non vengono validati.
- L'escaping XML dipende da `cgi.escape` ed è applicato soltanto ad alcuni valori.
- Il file DOCX in ingresso viene trattato come archivio ZIP senza limiti espliciti su dimensioni o rapporto di compressione.

I report Nessus e i relativi output possono contenere informazioni sensibili, come indirizzi IP, versioni software, configurazioni ed evidenze tecniche. Devono quindi essere conservati e condivisi secondo le regole di sicurezza dell'organizzazione.

## 10. Miglioramenti raccomandati

Per rendere lo strumento utilizzabile in modo affidabile si raccomanda di:

1. migrare il codice a una versione supportata di Python 3;
2. usare `argparse` e fornire un messaggio `--help`;
3. usare il modulo `csv` con delimitatore `|`, quoting ed encoding UTF-8 espliciti;
4. rappresentare le vulnerabilità con una struttura dati definita e validata;
5. deduplicare mediante una chiave stabile, per esempio host, plugin ID, porta e protocollo;
6. usare eccezioni specifiche e registrare gli errori;
7. ordinare severity, plugin e target in modo deterministico;
8. correggere la classificazione `Critical` e decidere esplicitamente se includere gli elementi `Info`;
9. generare il DOCX tramite una libreria dedicata, ad esempio `python-docx`, oppure usare veri segnaposto nel modello;
10. aggiungere test automatici con report Nessus minimi, campi mancanti e caratteri speciali;
11. scrivere i risultati prima in file temporanei e rinominarli soltanto a elaborazione completata;
12. produrre un riepilogo finale con numero di host, vulnerabilità, duplicati ed eventuali record scartati.

## 11. Risoluzione dei problemi

### `ImportError: No module named lxml`

La libreria `lxml` non è installata nell'ambiente Python utilizzato.

### `AttributeError: module 'cgi' has no attribute 'escape'`

Lo script viene eseguito con una versione moderna di Python. `cgi.escape` deve essere sostituito con `html.escape`.

### Errore relativo all'ordinamento dei dizionari

La deduplicazione del codice originale non è compatibile con Python 3. Deve essere sostituita con una deduplicazione basata su chiavi esplicite.

### Il CSV non viene creato

Il codice intercetta e ignora gli errori di I/O. Verificare manualmente permessi, percorso di destinazione e compatibilità tra stringhe e byte.

### Il Word è danneggiato o non si apre

Possibili cause:

- modello `.docx` non valido;
- valori non correttamente sottoposti a escaping XML;
- XML WordprocessingML generato non valido;
- stile o risorsa richiesta non presente nel modello;
- elaborazione interrotta prima della chiusura dell'archivio ZIP.

## 12. Avvertenza operativa

Prima di usare lo script su report reali è opportuno lavorare su copie dei file, utilizzare dati di test e verificare manualmente entrambi gli output. Il codice originale dovrebbe essere considerato uno strumento legacy o un prototipo, non un componente pronto per un processo di reporting in produzione.
