package com.appCifratura.backend.motoreCifratura;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class GestoreIdentita
{

    private static final String NOME_FILE_DB = "wallet.db";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int ITERATIONS = 65536;

    public static KeyPair generaNuovaIdentita() throws Exception
    {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        return kpg.generateKeyPair();

    }

    private static SecretKey derivaChiave(char[] password, byte[] salt) throws Exception
    {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");

    }

    public static void salvaDatabase(DatabaseChiavi db, char[] password) throws Exception
    {

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey aesKey = derivaChiave(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(db);
        oos.close();

        byte[] dbCifrato = cipher.doFinal(baos.toByteArray());

        try(FileOutputStream fos = new FileOutputStream(NOME_FILE_DB))
        {

            fos.write(salt);
            fos.write(iv);
            fos.write(dbCifrato);

        }

    }

    public static DatabaseChiavi caricaDatabase(char[] password) throws Exception
    {

        File f = new File(NOME_FILE_DB);
        if(!f.exists())
        {

            return new DatabaseChiavi();

        }

        try(FileInputStream fis = new FileInputStream(f))
        {

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            fis.read(salt);
            fis.read(iv);

            byte[] datiCifrati = fis.readAllBytes();

            SecretKey aesKey = derivaChiave(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

            byte[] dbDecifrato = cipher.doFinal(datiCifrati);

            ByteArrayInputStream bais = new ByteArrayInputStream(dbDecifrato);
            ObjectInputStream ois = new ObjectInputStream(bais);
            return (DatabaseChiavi) ois.readObject();

        }

    }

    public static void pulisciPassword(char[] password)
    {

        if(password != null)
        {

            Arrays.fill(password, '\0');

        }

    }

    public static void cambiaMasterPassword(DatabaseChiavi db, char[] vecchiaPassword, char[] nuovaPassword, char[]conferma, char[] masterPassword) throws Exception
    {

        for(int i=0; i<nuovaPassword.length; i++)
        {

            if(vecchiaPassword.length != masterPassword.length)
                throw new IllegalArgumentException("La vecchia password non coincide con la master password attuale.");

            if(vecchiaPassword[i] != masterPassword[i])
                throw new IllegalArgumentException("La vecchia password non coincide con la master password attuale.");

        }

        if(nuovaPassword == null || nuovaPassword.length < 8)
        {

            throw new IllegalArgumentException("La nuova password deve essere di almeno 8 caratteri.");

        }
        for(int i=0; i<nuovaPassword.length; i++)
        {

            if(nuovaPassword.length != conferma.length)
                throw new IllegalArgumentException("La nuova password non coincide con quella di conferma.");

            if(nuovaPassword[i] != conferma[i])
                throw new IllegalArgumentException("La nuova password e quella di conferma non coincidono");

        }

        salvaDatabase(db, nuovaPassword);

    }

    public static void wipeDatiSensibili(DatabaseChiavi db, char[] masterPassword)
    {

        pulisciPassword(masterPassword);

        if(db != null)
        {

            db.miaChiavePrivata = null;
            db.miaChiavePubblica = null;
            if(db.rubricaContatti != null)
            {

                db.rubricaContatti.clear();

            }

        }

        System.gc();

    }

}