package com.appCifratura.backend.motoreCifratura;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.SecureRandom;

public class SecureDelete
{

    //questo metodo esegue il secure-delete di un file che gli si passa, ovvero lo sovrascrive totalmente con dati randomici,
    //lo rinomina randomicamente e poi lo elimina effettivamente
    public static void eseguiSecureDelete(File file) throws Exception {

        //se il file non esiste returno o se non posso scriverlo
        if (!file.exists() || !file.canWrite())
            return;

        long length = file.length();
        SecureRandom random = new SecureRandom();

        //sovrascrivo il vecchio file con byte fittizzi
        try (RandomAccessFile raf = new RandomAccessFile(file, "rws"))
        {

            //aumento la dimensione del buffer a 1MB per compensare l'overhead del SecureRandom
            byte[] data = new byte[4 * (1024 * 1024)];
            long currentPos = 0;

            while (currentPos < length)
            {

                random.nextBytes(data);

                int toWrite = (int) Math.min(data.length, length - currentPos);
                raf.write(data, 0, toWrite);
                currentPos += toWrite;

            }

            //forzo la scrittura dei dati sul disco
            raf.getFD().sync();

        }

        //rinomino in maniera casuale il file sorgente
        String nomeCasuale = "temp_" + System.nanoTime() + ".tmp";
        File fileDaEliminare = new File(file.getParent(), nomeCasuale);

        if (file.renameTo(fileDaEliminare))
        {

            try
            {

                java.nio.file.Files.deleteIfExists(fileDaEliminare.toPath());

            }
            catch(Exception e)
            {

                fileDaEliminare.deleteOnExit();

            }

        }
        else
        {

            try
            {

                java.nio.file.Files.deleteIfExists(file.toPath());

            }
            catch(Exception e)
            {

                file.deleteOnExit();

            }

        }

    }

}
