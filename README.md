# JavaSecureFileEncryptor v1.1.0

Un'applicazione desktop professionale per la cifratura di file e la gestione sicura delle identità digitale. Sviluppata in Java 21, implementa standard crittografici "state-of-the-art" per garantire la massima privacy e integrità dei dati.

## Architettura di Sicurezza

Il cuore del progetto è stato progettato per resistere ad attacchi avanzati e prevenire la perdita accidentale di dati:

* **Cifratura Ibrida:** Protezione dei file tramite **AES-256 GCM** (Authenticated Encryption) con chiavi scambiate via **RSA-4096**.
* **Hardening del Database:** Il wallet locale è cifrato e protetto da **PBKDF2 con 600.000 iterazioni** (SHA-256). Questo rende i tentativi di brute-force sulla Master Password estremamente lenti e costosi.
* **Resilienza dei Dati:** Implementato il **salvataggio atomico** con gestione automatica dei backup (`.bak`). Se il sistema si interrompe durante una scrittura, i tuoi dati rimangono integri.
* **Sicurezza Attiva:**
    * **Auto-Lock:** Blocco automatico dell'app dopo 3 minuti di inattività.
    * **Memory Wipe:** Sovrascrittura degli array di caratteri sensibili in RAM subito dopo l'uso.
    * **Secure Delete:** Cancellazione sicura dei file originali con sovrascrittura per impedire il recupero forense.

## Caratteristiche Principali

* **Gestione Identità:** Generazione chiavi RSA, esportazione pubblica e rubrica contatti integrata in formato JSON versionato.
* **Interfaccia Fluida:** GUI multi-thread che garantisce la reattività dell'interfaccia anche durante la cifratura di file di grandi dimensioni.
* **Cross-Platform:** Gestione intelligente dei percorsi di sistema (`AppData` su Windows, `Application Support` su macOS, directory nascoste su Linux).

## Installazione e Avvio

### Requisiti
* **Java 21** o superiore installato.

### Esecuzione
Scarica l'ultimo JAR dalla sezione [Releases] e avvia con il comando specificato nella descrizione di essa per impedire il dump della memoria da parte di processi esterni.

