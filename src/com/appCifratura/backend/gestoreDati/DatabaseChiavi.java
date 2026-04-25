package com.appCifratura.backend.gestoreDati;

import java.util.HashMap;

public class DatabaseChiavi
{

    //ogni volta che aggiungi campi, aumenta questo numero
    public int versione = 2;

    public byte[] miaChiavePrivata;
    public byte[] miaChiavePubblica;

    public HashMap<String, byte[]> rubricaContatti = new HashMap<>();

    public java.util.List<String> logAttivita = new java.util.ArrayList<>();
    private static final int MAX_LOGS = 300;

    public DatabaseChiavi()
    {

        //anche qua da incrementare
        this.versione = 2;

    }

    public void aggiungiLog(String messaggio)
    {

        String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss"));
        logAttivita.add(0, "[" + timestamp + "] " + messaggio);

        while(logAttivita.size() > MAX_LOGS)
        {

            logAttivita.remove(logAttivita.size() - 1);

        }

    }

}