package com.appCifratura.backend.gestoreDati;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

public class DatabaseChiavi implements Serializable
{

    private static final long serialVersionUID = 1L;

    public PrivateKey miaChiavePrivata;
    public PublicKey miaChiavePubblica;

    public HashMap<String, PublicKey> rubricaContatti = new HashMap<>();

}