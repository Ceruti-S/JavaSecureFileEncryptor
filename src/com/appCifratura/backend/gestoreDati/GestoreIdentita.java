package com.appCifratura.backend.gestoreDati;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.security.spec.X509EncodedKeySpec;

public class GestoreIdentita
{

    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int ITERATIONS = 600000;

    private static final String NOME_CARTELLA = ".appCifratura";
    private static final String NOME_FILE_DB_BASE = "wallet.db";

    private static final String PERCORSO_COMPLETO = getPathSorgente() + File.separator + NOME_FILE_DB_BASE;

    private static String getPathSorgente()
    {

        String os = System.getProperty("os.name").toLowerCase();
        String path;

        if(os.contains("win"))
        {

            path = System.getenv("AppData");
            if (path == null)
                path = System.getProperty("user.home");

        }
        else if(os.contains("mac"))
        {

            path = System.getProperty("user.home") + "/Library/Application Support";

        }
        else
        {

            path = System.getProperty("user.home");

        }

        File directory = new File(path, NOME_CARTELLA);

        if(!directory.exists())
        {

            directory.mkdirs();

        }

        return directory.getAbsolutePath();

    }

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

        File fileOriginale = new File(PERCORSO_COMPLETO);
        File fileBackup = new File(PERCORSO_COMPLETO + ".bak");

        if(fileOriginale.exists())
        {

            if(fileBackup.exists())
                fileBackup.delete();
            fileOriginale.renameTo(fileBackup);

        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(db);
        byte[] datiDaCifrare = json.getBytes(StandardCharsets.UTF_8);

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey aesKey = derivaChiave(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] dbCifrato = cipher.doFinal(datiDaCifrare);

        try(FileOutputStream fos = new FileOutputStream(PERCORSO_COMPLETO))
        {

            fos.write(salt);
            fos.write(iv);
            fos.write(dbCifrato);

        }

    }

    public static DatabaseChiavi caricaDatabase(char[] password) throws Exception
    {

        File f = new File(PERCORSO_COMPLETO);
        File b = new File(PERCORSO_COMPLETO + ".bak");

        if (!f.exists() && !b.exists())
        {

            return new DatabaseChiavi();

        }

        if(f.exists())
        {

            try
            {

                return leggiFile(f, password);

            }
            catch(Exception e)
            {

                System.err.println("File principale corrotto, tento il ripristino dal backup...");

            }

        }

        if(b.exists())
        {

            try
            {

                DatabaseChiavi dbRecuperato = leggiFile(b, password);
                salvaDatabase(dbRecuperato, password);

                return dbRecuperato;

            }
            catch(Exception e)
            {

                throw new Exception("Errore critico: database e backup sono entrambi illeggibili o password errata.");

            }

        }

        throw new Exception("Impossibile accedere ai dati del wallet.");

    }

    public static boolean esisteDatabase()
    {

        return new File(PERCORSO_COMPLETO).exists();

    }

    public static PublicKey convertiByteInChiavePubblica(byte[] encodedKey) throws Exception
    {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));

    }

    private static DatabaseChiavi leggiFile(File file, char[] password) throws Exception
    {

        try(FileInputStream fis = new FileInputStream(file))
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

            String json = new String(dbDecifrato, StandardCharsets.UTF_8);
            Gson gson = new Gson();
            DatabaseChiavi db = gson.fromJson(json, DatabaseChiavi.class);

            return db;

        }

    }

    public static PrivateKey convertiByteInChiavePrivata(byte[] encodedKey) throws Exception
    {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));

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

        if (!Arrays.equals(vecchiaPassword, masterPassword)) {
            throw new IllegalArgumentException("La vecchia password non coincide con quella attuale.");
        }

        if (nuovaPassword == null || nuovaPassword.length < 8) {
            throw new IllegalArgumentException("La nuova password deve essere di almeno 8 caratteri.");
        }
        if (!Arrays.equals(nuovaPassword, conferma)) {
            throw new IllegalArgumentException("La nuova password e quella di conferma non coincidono.");
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