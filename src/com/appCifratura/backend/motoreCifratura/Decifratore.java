package com.appCifratura.backend.motoreCifratura;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import static com.appCifratura.backend.motoreCifratura.SecureDelete.eseguiSecureDelete;

public class Decifratore
{

    //definisco la grandezza in bit del buffer che userò per leggere i file a pezzi
    private static final int BUFFER_SIZE = 8192;

    //questo metodo fa la stessa cosa della sua controparte di CIfratore.java ma all'esatto contrario e prende la privateKey dell'rsa
    public static void decifraFile(File fileCifrato, PrivateKey rsaPrivateKey, boolean secureDelete) throws Exception
    {

        try(DataInputStream dis = new DataInputStream(new FileInputStream(fileCifrato)))
        {

            int lunghezzaChiave = dis.readInt();
            if(lunghezzaChiave <= 0 || lunghezzaChiave > 2048)
                throw new IOException("Vulnerabilità OOM rilevata: lunghezza chiave non valida");

            byte[] chiaveAesCifrata = new byte[lunghezzaChiave];
            dis.readFully(chiaveAesCifrata);

            //decifro la chiave aes con la chiave rsa privata
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey);
            SecretKey aesKey = (SecretKey)rsaCipher.unwrap(chiaveAesCifrata, "AES", Cipher.SECRET_KEY);

            //leggo e decifro Il nome in modo isolato e autenticato
            byte[] ivName = new byte[12];
            dis.readFully(ivName);

            int lunghezzaNome = dis.readInt();
            if (lunghezzaNome <= 0 || lunghezzaNome > 1024)
                throw new IOException("Lunghezza nome file non valida");

            byte[] nomeCifrato = new byte[lunghezzaNome];
            dis.readFully(nomeCifrato);

            Cipher nameCipher = Cipher.getInstance("AES/GCM/NoPadding");
            nameCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivName));

            //doFinal verifica il tag prima che usiamo il nome
            byte[] nomeDecifratoBytes = nameCipher.doFinal(nomeCifrato);
            String nomeOriginaleRaw = new String(nomeDecifratoBytes, StandardCharsets.UTF_8);
            String nomeOriginale = new File(nomeOriginaleRaw).getName();

            //leggo IV e preparo la decifratura del file
            byte[] ivFile = new byte[12];
            dis.readFully(ivFile);

            Cipher fileCipher = Cipher.getInstance("AES/GCM/NoPadding");
            fileCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, ivFile));

            //preparo il file di destinazione decifrato
            File fileRipristinato = new File(fileCifrato.getParent(), nomeOriginale);

            //decifro il file a pezzi e lo scrivo
            try(FileOutputStream fos = new FileOutputStream(fileRipristinato))
            {

                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;

                while((bytesRead = dis.read(buffer)) != -1)
                {

                    byte[] output = fileCipher.update(buffer, 0, bytesRead);
                    if(output != null)
                        fos.write(output);

                }

                //controllo l'integrità del file col tag GCM
                byte[] finalBytes = fileCipher.doFinal();
                if(finalBytes != null)
                    fos.write(finalBytes);

            }
            catch(Exception e)
            {

                if(fileRipristinato != null && fileRipristinato.exists())
                    fileRipristinato.delete();
                throw e;

            }

        }

        //se l'utente lo ha selezionato, faccio il secure-delete del file cifrato
        if(secureDelete)
            eseguiSecureDelete(fileCifrato);

    }

}
