package com.appCifratura.backend.motoreCifratura;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.UUID;

import static com.appCifratura.backend.motoreCifratura.SecureDelete.eseguiSecureDelete;

public class Cifratore
{

    //definisco la grandezza in bit del buffer che userò per leggere i file a pezzi
    private static final int BUFFER_SIZE = 8192;

    //prende in ingresso il file(oggetto che punta al percorso del file) non criptato e ne crea uno nuovo criptato scrivendolo
    //su "fileDestinazione", prende in ingresso anche la publickey rsa per cifrare la chiave aes-256 e un boolean che se è true
    //il programma farà il safe-delete del file sorgente dopo aver cifrato
    // /!\il programma CREA il file criptato quindi non deve già esistere sul percorso dove viene salvato altrimenti verrà sovrascritto quello già presente
    public static File criptaFile(File fileSorgente, PublicKey rsaPublicKey, boolean secureDelete) throws Exception
    {

        //creo il nome anonimo del file criptato
        String nomeAnonimo = UUID.randomUUID().toString() +  ".crypt";
        //creo il file dove scriverò i dati criptati
        File fileDestinazione = new File(fileSorgente.getParent(), nomeAnonimo);

        //genero la chiave AES-256
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        SecureRandom random = new SecureRandom();

        //genero IV separati: uno per cifrare il nome, uno per il contenuto
        byte[] ivName = new byte[12];
        random.nextBytes(ivName);

        byte[] ivFile = new byte[12];
        random.nextBytes(ivFile);

        //cifro la chiave AES con RSA-OAEP
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, rsaPublicKey);
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);

        //cifro il nome in un blocco isolato e autenticato
        String nomeOriginale = fileSorgente.getName();
        byte[] nomeBytes = nomeOriginale.getBytes(StandardCharsets.UTF_8);
        if (nomeBytes.length > 255) throw new IllegalArgumentException("Nome file troppo lungo");

        Cipher nameCipher = Cipher.getInstance("AES/GCM/NoPadding");
        nameCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, ivName));
        byte[] nomeCifrato = nameCipher.doFinal(nomeBytes); //doFinal garantisce che ci sia il tag GCM

        //preparo il motore per cifrare il file
        Cipher fileCipher = Cipher.getInstance("AES/GCM/NoPadding");
        fileCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, ivFile));

        boolean operazioneCompletata = false;

        try
        {

            //scrivo direttamente sul file i dati che cifro
            try(FileInputStream fis = new FileInputStream(fileSorgente); DataOutputStream dos = new DataOutputStream(new FileOutputStream(fileDestinazione)))
            {

                //scrivo Header: len(chiave) + chiave
                dos.writeInt(encryptedAesKey.length);
                dos.write(encryptedAesKey);

                //scrivo Header Nome: ivName + len(nomeCifrato) + nomeCifrato
                dos.write(ivName);
                dos.writeInt(nomeCifrato.length);
                dos.write(nomeCifrato);

                //scrivo Header File: ivFile
                dos.write(ivFile);

                //cifro a pezzi il file per non mandare in overflow la RAM
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while((bytesRead = fis.read(buffer)) != -1)
                {

                    byte[] output = fileCipher.update(buffer, 0, bytesRead);
                    if(output != null)
                        dos.write(output);

                }

                //aggiungo l'authentication tag finale GCM del file
                byte[] finalBytes = fileCipher.doFinal();
                if(finalBytes != null)
                    dos.write(finalBytes);

            }

            operazioneCompletata = true;
        }
        finally
        {

            //se c'è un errore durante la scrittura, elimino il file parziale/corrotto
            if (!operazioneCompletata && fileDestinazione.exists())
            {

                fileDestinazione.delete();

            }

        }

        //se l'utente lo ha selezionato e l'operazione è andata a buon fine faccio il secure-delete
        if(operazioneCompletata && secureDelete)
            eseguiSecureDelete(fileSorgente);

        return fileDestinazione; //returno il file criptato almeno posso sapere come lo ho salvato sul disco

    }

}
