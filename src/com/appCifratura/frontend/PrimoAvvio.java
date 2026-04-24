package com.appCifratura.frontend;

import com.appCifratura.backend.gestoreDati.DatabaseChiavi;
import com.appCifratura.backend.gestoreDati.GestoreIdentita;
import com.appCifratura.backend.gestorePassword.Generator;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.security.KeyPair;
import java.util.Arrays;

public class PrimoAvvio extends JFrame {

    private final JPasswordField passField;
    private final JPasswordField confirmPassField;
    private final JButton btnCreate;
    private final JProgressBar progressBar;

    private final JProgressBar securityBar;
    private final JLabel lblFeedback;
    private final JButton btnSuggerisci;

    public PrimoAvvio() {
        setTitle("SecureVault - Configurazione Iniziale");
        setSize(550, 500);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        JPanel mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(8, 20, 8, 20);
        gbc.weightx = 1.0;

        Font fieldFont = new Font("Arial", Font.PLAIN, 16);
        char echoChar = '●';

        // --- PASSWORD PRINCIPALE ---
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel("Scegli la tua Master Password (min 8 caratteri):"), gbc);

        passField = new JPasswordField(30);
        autoConfiguraCampo(passField, fieldFont, echoChar);
        JPanel passWrapper = creaPasswordWrapper(passField);
        gbc.gridy = 1; mainPanel.add(passWrapper, gbc);

        // --- BARRA SICUREZZA ---
        securityBar = new JProgressBar(0, 4);
        securityBar.setPreferredSize(new Dimension(100, 12));
        gbc.gridy = 2; mainPanel.add(securityBar, gbc);

        lblFeedback = new JLabel("Inserisci una password");
        lblFeedback.setFont(new Font("Arial", Font.ITALIC, 11));
        gbc.gridy = 3; mainPanel.add(lblFeedback, gbc);

        btnSuggerisci = new JButton("Genera una password sicura");
        gbc.gridy = 4; mainPanel.add(btnSuggerisci, gbc);

        // --- CONFERMA ---
        gbc.gridy = 5; mainPanel.add(new JLabel("Conferma Password:"), gbc);

        confirmPassField = new JPasswordField(30);
        autoConfiguraCampo(confirmPassField, fieldFont, echoChar);
        JPanel confWrapper = creaPasswordWrapper(confirmPassField);
        gbc.gridy = 6; mainPanel.add(confWrapper, gbc);

        // --- PULSANTE CREAZIONE ---
        btnCreate = new JButton("CREA IL TUO WALLET");
        btnCreate.setFont(new Font("Arial", Font.BOLD, 14));
        btnCreate.setBackground(new Color(50, 120, 200));
        btnCreate.setForeground(Color.WHITE);
        gbc.gridy = 7;
        gbc.insets = new Insets(25, 20, 10, 20);
        mainPanel.add(btnCreate, gbc);

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);

        add(mainPanel, BorderLayout.CENTER);
        add(progressBar, BorderLayout.SOUTH);

        // --- LOGICA LISTENER ---
        passField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { aggiorna(); }
            public void removeUpdate(DocumentEvent e) { aggiorna(); }
            public void changedUpdate(DocumentEvent e) { aggiorna(); }
            private void aggiorna() {
                String p = new String(passField.getPassword());
                var res = Generator.analizzaPassword(p);
                securityBar.setValue(res.score());
                securityBar.setForeground(res.colore());
                lblFeedback.setText(res.messaggio());
                lblFeedback.setForeground(res.colore());
            }
        });

        btnSuggerisci.addActionListener(e -> {
            String suggerita = Generator.generatePassword(30, true, true, true);
            passField.setText(suggerita);
            confirmPassField.setText(suggerita);
            JOptionPane.showMessageDialog(this, "Password generata con successo.\nCopiata automaticamente nei campi.");
        });

        btnCreate.addActionListener(e -> avviaInizializzazione());
    }

    private void autoConfiguraCampo(JPasswordField f, Font font, char echo) {
        f.setFont(font);
        f.setEchoChar(echo);
    }

    private JPanel creaPasswordWrapper(JPasswordField field) {
        JButton btn = new JButton("vedi");
        btn.setFocusable(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        char originalEcho = field.getEchoChar();

        btn.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent e) { field.setEchoChar((char) 0); }
            public void mouseReleased(java.awt.event.MouseEvent e) { field.setEchoChar(originalEcho); }
        });

        JPanel wrapper = new JPanel(new BorderLayout(5, 0));
        wrapper.add(field, BorderLayout.CENTER);
        wrapper.add(btn, BorderLayout.EAST);
        return wrapper;
    }

    private void avviaInizializzazione() {
        char[] pass = passField.getPassword();
        char[] confirm = confirmPassField.getPassword();

        if (pass.length > 100) {
            JOptionPane.showMessageDialog(this, "Password troppo lunga (max 100).");
            return;
        }

        if (validazione(pass, confirm)) {
            btnCreate.setEnabled(false);
            progressBar.setVisible(true);

            // Operazione intensiva in un thread separato
            new Thread(() -> {
                try {
                    // Generazione chiavi RSA
                    KeyPair kp = GestoreIdentita.generaNuovaIdentita();

                    DatabaseChiavi nuovoDb = new DatabaseChiavi();
                    // IMPORTANTE: Salviamo l'encoding (byte[]) non l'oggetto interfaccia
                    nuovoDb.miaChiavePrivata = kp.getPrivate().getEncoded();
                    nuovoDb.miaChiavePubblica = kp.getPublic().getEncoded();

                    // Salvataggio su disco cifrato con la Master Password
                    GestoreIdentita.salvaDatabase(nuovoDb, pass);

                    // Pulizia array per sicurezza
                    Arrays.fill(pass, '\0');
                    Arrays.fill(confirm, '\0');

                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this, "Wallet creato con successo!");
                        this.dispose();
                        new AppGUI().setVisible(true);
                    });

                } catch (Exception ex) {
                    ex.printStackTrace();
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(this, "Errore durante la creazione: " + ex.getMessage());
                        btnCreate.setEnabled(true);
                        progressBar.setVisible(false);
                    });
                }
            }).start();
        }
    }

    private boolean validazione(char[] p1, char[] p2) {
        if (p1.length < 8) {
            JOptionPane.showMessageDialog(this, "La password deve avere almeno 8 caratteri.");
            return false;
        }

        if (!Arrays.equals(p1, p2)) {
            JOptionPane.showMessageDialog(this, "Le password non coincidono!");
            return false;
        }

        return true;
    }
}