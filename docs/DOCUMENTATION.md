# Documentazione Tecnica: JavaSecureFileEncryptor v1.1.0

## 1. Introduzione e Visione del Progetto
**JavaSecureFileEncryptor** è un'applicazione desktop di livello professionale dedicata alla sicurezza informatica e alla protezione della privacy. Il software implementa un'architettura a **Cifratura Ibrida**, combinando la robustezza degli algoritmi asimmetrici per la gestione delle identità e l'efficienza degli algoritmi simmetrici per il trattamento dei dati massivi.

---

## 2. Architettura Crittografica

### 2.1 Standard e Algoritmi
L'applicazione si basa esclusivamente su primitive crittografiche fornite dalla **Java Cryptography Architecture (JCA)**, configurate secondo gli standard odierni più rigorosi:

* **Asimmetrico (Identità):** RSA-4096 con padding **OAEP** (Optimal Asymmetric Encryption Padding) e hashing SHA-256. Utilizzato per lo scambio sicuro di chiavi e l'identificazione univoca degli utenti.
* **Simmetrico (Dati):** AES-256 in modalità **GCM** (Galois/Counter Mode). Questa modalità fornisce l'**Authenticated Encryption (AEAD)**, garantendo simultaneamente riservatezza e integrità (rilevamento manomissioni).
* **Derivazione Chiave (KDF):** **PBKDF2WithHmacSHA256**. Trasforma la Master Password in una chiave AES a 256 bit applicando **600.000 iterazioni** e un **Salt casuale di 16 byte**.

### 2.2 Il Formato File `.crypt`
Ogni file cifrato prodotto dall'app segue una struttura binaria deterministica:
1.  **RSA Header (Variabile):** Contiene la chiave AES di sessione cifrata con la chiave pubblica del destinatario.
2.  **IV Principale (12 byte):** Il vettore di inizializzazione per il payload del file.
3.  **IV Nome (12 byte):** Vettore separato per la cifratura del nome originale del file.
4.  **Payload Cifrato:** I dati effettivi del file trasformati in ciphertext.
5.  **GCM Auth Tag (16 byte):** Tag di autenticazione per verificare che il file non sia stato alterato.

---

## 3. Gestione della Persistenza: Il Wallet

### 3.1 Hardening del Database locale
Il file `wallet.db` non contiene dati leggibili, ma un oggetto JSON cifrato. 
* **Formato:** Serializzazione tramite libreria **Google GSON**.
* **Versioning:** Il database include un campo `versione` per permettere la migrazione automatica dello schema nelle release future.
* **Sicurezza:** Ogni volta che il wallet viene salvato, viene generato un nuovo `Salt` e un nuovo `IV`, rendendo il file diverso su disco anche se i dati interni non cambiano.

### 3.2 Protocollo di Salvataggio Atomico
Per eliminare il rischio di perdita dati durante la scrittura (es. crash di sistema):
1.  Viene creato un backup temporaneo del vecchio database (`wallet.db.bak`).
2.  Viene scritto il nuovo file `wallet.db`.
3.  In caso di errore durante il caricamento (es. file corrotto), l'applicazione tenta automaticamente il ripristino dal file `.bak`.

---

## 4. Protocolli di Sicurezza Attiva

### 4.1 Gestione della Memoria (RAM)
* **Zero-Footprint:** Le password e le chiavi private vengono memorizzate in `char[]` o `byte[]`. Subito dopo l'operazione crittografica, questi array vengono sovrascritti con zeri (`\0`) per impedire il recupero tramite dump della RAM.
* **Anti-Attach:** Si raccomanda l'avvio con `-XX:+DisableAttachMechanism` per bloccare debugger o malware che tentano di iniettarsi nel processo JVM.

### 4.2 Secure Delete (Data Sanitization)
La funzione di eliminazione sicura segue un protocollo di sovrascrittura a basso livello:
1.  Sovrascrittura del file originale con dati casuali (`SecureRandom`).
2.  Sincronizzazione forzata del descrittore del file (`FileDescriptor.sync()`).
3.  Cancellazione logica dal file system.

### 4.3 Session Management
* **Auto-Lock:** Un timer di background monitora l'attività dell'utente. Dopo **180 secondi** di inattività, i dati sensibili vengono scaricati dalla memoria e l'interfaccia torna alla schermata di Login.

---

## 5. Implementazione Tecnica

### 5.1 Requisiti di Sistema
* **Runtime:** Java 21+ (LTS).
* **Dipendenze:** * `com.google.code.gson`: Gestione JSON.
    * `com.nulab-inc.zxcvbn`: Valutazione entropia password.

### 5.2 Struttura dei Package
* `com.appCifratura.backend.motoreCifratura`: Logica AES/RSA di basso livello.
* `com.appCifratura.backend.gestoreDati`: Gestione del wallet, persistenza e PBKDF2.
* `com.appCifratura.frontend`: Interfaccia grafica Swing (AppGUI, PrimoAvvio).

---

## 6. Sviluppi Futuri (Roadmap)
* **Cifratura Batch:** Supporto alla cifratura ricorsiva di intere cartelle.

---
*Documentazione v1.1.0 - Rilasciata sotto licenza protetta.*
