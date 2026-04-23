# Documentazione Tecnica: JavaSecureFileEncryptor

## 1. Panoramica del Progetto
**JavaCryptoWallet** è un'applicazione desktop progettata per la protezione della privacy e la gestione sicura dei file. Utilizza un modello di **cifratura ibrida** che combina la potenza della crittografia asimmetrica (RSA) per lo scambio delle chiavi e la velocità della crittografia simmetrica (AES) per la protezione dei dati massivi.

---

## 2. Architettura Crittografica
L'applicazione si basa su standard industriali per garantire l'integrità e la riservatezza.

### 2.1 Algoritmi Utilizzati
* **RSA-4096 (OAEP Padding):** Per la protezione della chiave simmetrica e l'identità digitale.
* **AES-256 GCM (Galois/Counter Mode):** Per la cifratura dei file (garantisce riservatezza e integrità).
* **PBKDF2WithHmacSHA256:** Per derivare la chiave del database (`wallet.db`) dalla Master Password.

### 2.2 Struttura del File Cifrato (.crypt)
Il formato binario include:
1. Lunghezza Chiave RSA (4 byte)
2. Chiave AES cifrata (Variabile)
3. IV Principale (12 byte) + IV Nome (12 byte)
4. Lunghezza e Nome File Cifrato
5. Payload (Dati effettivi)
6. Auth Tag GCM (16 byte) per la verifica integrità.

---

## 3. Protocolli di Sicurezza Avanzati
* **Zero-Footprint Memory:** Uso di `char[]` sovrascritti con zeri e Shutdown Hook per pulire la RAM.
* **Auto-Lock:** Blocco automatico dopo 3 minuti di inattività totale.
* **Secure Delete:** Sovrascrittura del file originale con byte casuali prima della cancellazione.

---

## 4. Flusso di Lavoro (GUI)
* **Identità:** Gestione chiavi RSA e rubrica contatti.
* **Cifratura/Decifratura:** Uso di `SwingWorker` per non bloccare l'interfaccia e ProgressBar per feedback in tempo reale.

---

## 5. Requisiti
* **Java 21+** e nessuna libreria esterna (solo JCA standard).

---

## 6. Sviluppi Futuri
* Cifratura di cartelle (compressione ZIP).
* Steganografia (nascondere dati nelle immagini).
* Supporto multi-destinatario.

---
*Documentazione v1.0.0. - Creative Commons BY-NC 4.0*
