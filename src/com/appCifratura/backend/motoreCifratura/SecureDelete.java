package com.appCifratura.backend.motoreCifratura;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.SecureRandom;
import java.util.Arrays;

public class SecureDelete
{

    private static final int BUFFER_SIZE = 5 * 1024 * 1024;

    private static final int OVERWRITE_PASSES = 5;

    public static void eseguiSecureDelete(File file) throws Exception
    {

        if(!file.exists() || !file.canWrite())
            return;

        final long length = file.length();
        final SecureRandom random = new SecureRandom();

        try(RandomAccessFile raf = new RandomAccessFile(file, "rws"))
        {

            for(int pass = 0; pass < OVERWRITE_PASSES; pass++)
            {

                raf.seek(0);
                long currentPos = 0;

                byte[] data = new byte[(int) Math.min(BUFFER_SIZE, Math.max(length, 1))];

                while(currentPos < length)
                {

                    if(pass % 2 == 0)
                    {

                        random.nextBytes(data);

                    }
                    else
                    {

                        byte fillByte = ((pass / 2) % 2 == 0) ? (byte) 0x00 : (byte) 0xFF;
                        Arrays.fill(data, fillByte);

                    }

                    int toWrite = (int) Math.min(data.length, length - currentPos);
                    raf.write(data, 0, toWrite);
                    currentPos += toWrite;

                }

                raf.getFD().sync();

                Arrays.fill(data, (byte) 0);

            }

            raf.setLength(0);
            raf.getFD().sync();

        }

        String nomeCasuale = "tmp_" + System.nanoTime() + "_" + Thread.currentThread().getId() + ".del";
        File fileDaEliminare = new File(file.getParent(), nomeCasuale);

        if(file.renameTo(fileDaEliminare))
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