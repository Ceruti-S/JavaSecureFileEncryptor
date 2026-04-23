# JavaSecureFileEncryptor

Un'applicazione desktop robusta per la cifratura di file e la gestione sicura delle identità, sviluppata in Java. Il progetto implementa standard crittografici di alto livello per garantire la massima privacy e integrità dei dati.

## Caratteristiche Principali

* **Cifratura Ibrida:** Utilizza **RSA-4096** per lo scambio sicuro delle chiavi e **AES-256 GCM** per la protezione dei dati (autenticazione inclusa).
* **Gestione Identità:** Sistema integrato per generare coppie di chiavi, esportare la propria chiave pubblica e gestire una rubrica di contatti fidata.
* **Sicurezza Attiva:**
    * **Auto-Lock:** Blocco automatico dell'applicazione dopo 3 minuti di inattività.
    * **Memory Wipe:** Pulizia dei dati sensibili (array di caratteri) in RAM allo spegnimento o al logout.
    * **Secure Delete:** Cancellazione sicura dei file originali con sovrascrittura a più passaggi (anti-recupero).
* **Interfaccia Fluida:** GUI in Swing con processi in background e barra di progresso in tempo reale per gestire file di grandi dimensioni.

## Stack Tecnologico

* **Linguaggio:** Java 21+
* **Crittografia:** Java Cryptography Architecture (JCA)
* **GUI:** Java Swing
* **Algoritmi:** AES-256-GCM, RSA-OAEP-4096, SHA-256.

## Installazione

* **Utilizza i file nei tag (releases) già preparati**
