package com.appCifratura.backend.gestorePassword;

import javax.swing.*;
import java.awt.*;
import com.nulabinc.zxcvbn.Zxcvbn;
import com.nulabinc.zxcvbn.Strength;

public class Generator
{

    private static final Zxcvbn zxcvbn = new Zxcvbn();
    private static final java.security.SecureRandom rand = new java.security.SecureRandom();

    public record ResultSicurezza(Color colore, String messaggio, int score){}

    public static String generatePassword(int lunghezza, boolean upperCase, boolean numbers, boolean symbols)
    {

        StringBuilder poolBuilder = new StringBuilder("abcdefghijklmnopqrstuvwxyz");

        if (upperCase) poolBuilder.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (numbers)   poolBuilder.append("0123456789");
        if (symbols)   poolBuilder.append("!@#$%^&*()-_=+[]{}|;:,.<>?");

        String caratteriUtilizzabili = poolBuilder.toString();
        char [] caratteriUtilizzabiliArray = caratteriUtilizzabili.toCharArray();
        int caratteriUtilizzabiliArraySize = caratteriUtilizzabiliArray.length;

        boolean valida = false;
        StringBuilder password = new StringBuilder();

        do
        {

            password.setLength(0);
            char lastChar = '\0';

            for(int i=0; i<lunghezza; i++)
            {

                char nextChar;
                //ciclo finché non trovo un carattere diverso dal precedente
                do
                {

                    nextChar = caratteriUtilizzabiliArray[rand.nextInt(caratteriUtilizzabiliArraySize)];

                } while (nextChar == lastChar);

                password.append(nextChar);
                lastChar = nextChar;

            }

            if(password.length() >=128)
                valida = true;
            else
                valida = validaRequisiti(password, upperCase, numbers, symbols);

        }while(!valida);

        return password.toString();

    }

    private static boolean validaRequisiti(CharSequence password, boolean upper, boolean numbers, boolean symbols)
    {

        boolean hasLower = false, hasUpper = false, hasNum = false, hasSym = false;

        for (int i = 0; i < password.length(); i++)
        {

            char c = password.charAt(i);
            if (c >= 'a' && c <= 'z') hasLower = true;
            else if (c >= 'A' && c <= 'Z') hasUpper = true;
            else if (c >= '0' && c <= '9') hasNum = true;
            else hasSym = true;

        }

        if (!hasLower) return false;
        if (upper && !hasUpper) return false;
        if (numbers && !hasNum) return false;
        if (symbols && !hasSym) return false;

        return true;

    }

    public static ResultSicurezza analizzaPassword(String password)
    {

        if(password == null || password.length() < 6)
        {

            return new ResultSicurezza(new Color(255, 77, 77), "Password troppo corta.", 0);

        }

        String stringaDaAnalizzare = (password.length() > 128) ? password.substring(0, 128) : password;
        Strength strength = zxcvbn.measure(stringaDaAnalizzare);
        int score = strength.getScore();

        boolean haMaiuscole = false, haNumeri = false, haSimboli = false;

        for(int i=0; i<password.length(); i++)
        {

            char c = password.charAt(i);
            if (c >= 'a' && c <= 'z') continue;
            else if (c >= 'A' && c <= 'Z') haMaiuscole = true;
            else if (c >= '0' && c <= '9') haNumeri = true;
            else haSimboli = true;

            if(haMaiuscole && haNumeri && haSimboli)
                break;

        }

        int tipiDiCarattere = 1;
        if (haMaiuscole)
            tipiDiCarattere++;
        if (haNumeri)
            tipiDiCarattere++;
        if (haSimboli)
            tipiDiCarattere++;

        if(tipiDiCarattere == 1 && score > 1)
        {

            score = 1;

        }
        else if(tipiDiCarattere >= 3 && password.length() < 10 && score > 2)
        {

            score = 2;

        }

        if(score == 4 && (tipiDiCarattere < 4 || password.length() < 12))
        {

            score = 3;

        }

        Color colore = switch (score)
        {

            case 0 -> new Color(255, 77, 77);
            case 1 -> new Color(255, 166, 77);
            case 2 -> new Color(255, 255, 128);
            case 3 -> new Color(144, 238, 144);
            case 4 -> new Color(3, 244, 252);
            default -> Color.WHITE;

        };

        String warning = strength.getFeedback().getWarning();
        String messaggioFinale;

        if(warning == null || warning.isEmpty())
        {

            if(tipiDiCarattere < 4)
            {

                messaggioFinale = "Usa simboli, numeri e maiuscole.";

            }
            else
            {

                messaggioFinale = (score >= 3) ? "Ottima password!" : "Buona password.";

            }

        }
        else
        {

            messaggioFinale = warning;

        }

        return new ResultSicurezza(colore, messaggioFinale, score);

    }

}