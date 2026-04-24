package com.appCifratura.backend.gestoreDati;

import java.util.HashMap;

public class DatabaseChiavi
{

    //ogni volta che aggiungi campi, aumenta questo numero
    public int versione = 1;

    public byte[] miaChiavePrivata;
    public byte[] miaChiavePubblica;

    public HashMap<String, byte[]> rubricaContatti = new HashMap<>();

    public DatabaseChiavi()
    {

        //anche qua da incrementare
        this.versione = 1;

    }

}