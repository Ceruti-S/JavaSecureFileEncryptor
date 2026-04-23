package com.appCifratura.backend.motoreCifratura;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AppGUI extends JFrame
{

    private DatabaseChiavi db;
    private char[] masterPassword;

    private JProgressBar progressBar;

    private DefaultComboBoxModel<String> comboModel = new DefaultComboBoxModel<>();
    private DefaultListModel<String> listModelContatti = new DefaultListModel<>();
    private JList<String> listaGraficaContatti = new JList<>(listModelContatti);

    private Timer autoLockTimer;
    private static final int INACTIVITY_TIMEOUT = 3 * 60 * 1000; //3 minuti

    public AppGUI()
    {

        super("SecureVault - Motore Crittografico");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(650, 500);
        setLocationRelativeTo(null);

        if(!richiediAccesso())
        {

            System.exit(0);

        }

        inizializzaUI();

        autoLockTimer = new Timer(INACTIVITY_TIMEOUT, e -> lockApp());
        autoLockTimer.setRepeats(false);
        autoLockTimer.start();

        Toolkit.getDefaultToolkit().addAWTEventListener(event ->
        {

            if(autoLockTimer != null && autoLockTimer.isRunning())
            {

                autoLockTimer.restart();

            }

        }, AWTEvent.MOUSE_EVENT_MASK | AWTEvent.KEY_EVENT_MASK);

        Runtime.getRuntime().addShutdownHook(new Thread(() ->
        {

            System.out.println("Chiusura rilevata: avvio procedura di sicurezza...");
            GestoreIdentita.wipeDatiSensibili(db, masterPassword);

        }));

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        add(progressBar, BorderLayout.SOUTH);

    }

    private void lockApp()
    {

        GestoreIdentita.pulisciPassword(masterPassword);
        masterPassword = null;
        db = null;

        JOptionPane.showMessageDialog(this, "Sessione scaduta per inattività. L'app verrà bloccata.", "Auto-Lock", JOptionPane.WARNING_MESSAGE);

        this.setVisible(false);

        if(richiediAccesso())
        {

            sincronizzaListeContatti();
            this.setVisible(true);
            autoLockTimer.restart();

        }
        else
        {

            System.exit(0);

        }

    }

    private boolean richiediAccesso()
    {

        JPasswordField pf = new JPasswordField();
        int okCxl = JOptionPane.showConfirmDialog(null, pf, "Inserisci Master Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (okCxl == JOptionPane.OK_OPTION)
        {

            masterPassword = pf.getPassword();

            try
            {

                db = GestoreIdentita.caricaDatabase(masterPassword);

                if(db.miaChiavePrivata == null)
                {

                    JOptionPane.showMessageDialog(this, "Nessuna identità trovata. Generazione nuove chiavi RSA-4096...", "Prima Configurazione", JOptionPane.INFORMATION_MESSAGE);
                    KeyPair kp = GestoreIdentita.generaNuovaIdentita();
                    db.miaChiavePrivata = kp.getPrivate();
                    db.miaChiavePubblica = kp.getPublic();
                    GestoreIdentita.salvaDatabase(db, masterPassword);

                }

                return true;

            }
            catch (Exception e)
            {

                JOptionPane.showMessageDialog(null, "Password Errata o Database Corrotto!", "Errore Accesso", JOptionPane.ERROR_MESSAGE);
                GestoreIdentita.pulisciPassword(masterPassword);
                return false;

            }

        }

        return false;

    }

    private void inizializzaUI()
    {

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Cifra File", creaPannelloCifra());
        tabbedPane.addTab("Decifra File", creaPannelloDecifra());
        tabbedPane.addTab("Gestione Identità & Contatti", creaPannelloIdentita());
        add(tabbedPane);

    }

    private JPanel creaPannelloCifra()
    {

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton btnScegliFile = new JButton("Seleziona File da Cifrare");
        JLabel lblFileSelezionato = new JLabel("Nessun file selezionato");

        JComboBox<String> comboContatti = new JComboBox<>(comboModel);
        JButton btnRefresh = new JButton("Aggiorna");
        btnRefresh.setToolTipText("Aggiorna lista contatti");

        btnRefresh.addActionListener(e -> sincronizzaListeContatti());

        comboContatti.addItem("Me Stesso (Mia Chiave)");
        for(String nome : db.rubricaContatti.keySet())
        {

            comboContatti.addItem(nome);

        }

        JCheckBox chkSafeDelete = new JCheckBox("Abilita Secure Delete Originale");
        JButton btnCifra = new JButton("CIFRA FILE");
        btnCifra.setBackground(new Color(180, 50, 50));
        btnCifra.setForeground(Color.WHITE);
        btnCifra.setFont(new Font("SansSerif", Font.BOLD, 12));

        final File[] fileDaCifrare = {null};

        btnScegliFile.addActionListener(e ->
        {

            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            {

                fileDaCifrare[0] = chooser.getSelectedFile();
                lblFileSelezionato.setText(fileDaCifrare[0].getName());

            }

        });

        btnCifra.addActionListener(e ->
        {

            if (fileDaCifrare[0] == null)
                return;

            String contattoSel = (String) comboContatti.getSelectedItem();
            PublicKey chiaveDest = (contattoSel.equals("Me Stesso (Mia Chiave)"))
                    ? db.miaChiavePubblica : db.rubricaContatti.get(contattoSel);

            btnCifra.setEnabled(false);
            progressBar.setValue(0);
            progressBar.setVisible(true);

            SwingWorker<File, Integer> worker = new SwingWorker<>()
            {

                @Override
                protected File doInBackground() throws Exception
                {

                    return Cifratore.criptaFile(fileDaCifrare[0], chiaveDest, chkSafeDelete.isSelected(),
                            progress -> publish(progress));

                }

                @Override
                protected void process(java.util.List<Integer> chunks)
                {

                    int lastValue = chunks.get(chunks.size() - 1);
                    progressBar.setValue(lastValue);

                }

                @Override
                protected void done()
                {

                    try
                    {

                        File risultato = get(); // Ottiene il file prodotto o lancia eccezione
                        JOptionPane.showMessageDialog(AppGUI.this, "Operazione completata!");

                    }
                    catch(Exception ex)
                    {

                        JOptionPane.showMessageDialog(AppGUI.this, "Errore: " + ex.getCause().getMessage());

                    }
                    finally
                    {

                        btnCifra.setEnabled(true);
                        progressBar.setVisible(false);

                    }

                }

            };

            worker.execute();

        });

        JPanel rigaContatti = new JPanel(new BorderLayout(5, 0));
        rigaContatti.add(new JLabel("Destinatario: "), BorderLayout.WEST);
        rigaContatti.add(comboContatti, BorderLayout.CENTER);
        rigaContatti.add(btnRefresh, BorderLayout.EAST);

        gbc.gridx = 0; gbc.gridy = 0; panel.add(btnScegliFile, gbc);
        gbc.gridx = 1; panel.add(lblFileSelezionato, gbc);
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; panel.add(rigaContatti, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; panel.add(chkSafeDelete, gbc);
        gbc.gridy = 3; panel.add(btnCifra, gbc);

        return panel;

    }

    private JPanel creaPannelloDecifra()
    {

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JButton btnScegliFile = new JButton("Seleziona File (.crypt)");
        JLabel lblFileSelezionato = new JLabel("Nessun file selezionato");
        JCheckBox chkSafeDelete = new JCheckBox("Abilita Secure Delete (.crypt)");
        JButton btnDecifra = new JButton("DECIFRA FILE");
        btnDecifra.setBackground(new Color(50, 150, 50));
        btnDecifra.setForeground(Color.WHITE);
        btnDecifra.setFont(new Font("SansSerif", Font.BOLD, 12));

        final File[] fileDaDecifrare = {null};

        btnScegliFile.addActionListener(e ->
        {

            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION)
            {

                fileDaDecifrare[0] = chooser.getSelectedFile();
                lblFileSelezionato.setText(fileDaDecifrare[0].getName());

            }

        });

        btnDecifra.addActionListener(e ->
        {

            if(fileDaDecifrare[0] == null)
            {

                JOptionPane.showMessageDialog(this, "Seleziona un file!");
                return;

            }

            btnDecifra.setEnabled(false);
            progressBar.setValue(0);
            progressBar.setVisible(true);

            SwingWorker<Void, Integer> worker = new SwingWorker<>()
            {

                @Override
                protected Void doInBackground() throws Exception
                {

                    Decifratore.decifraFile(fileDaDecifrare[0], db.miaChiavePrivata, chkSafeDelete.isSelected(),
                            progress -> publish(progress));
                    return null;

                }

                @Override
                protected void process(java.util.List<Integer> chunks)
                {

                    int val = chunks.get(chunks.size() - 1);
                    progressBar.setValue(val);

                }

                @Override
                protected void done()
                {

                    try
                    {

                        get();
                        JOptionPane.showMessageDialog(AppGUI.this, "File decifrato con successo!");

                    }
                    catch(Exception ex)
                    {

                        JOptionPane.showMessageDialog(AppGUI.this, "Errore decifratura: " + ex.getCause().getMessage(), "Errore", JOptionPane.ERROR_MESSAGE);

                    }
                    finally
                    {

                        btnDecifra.setEnabled(true);
                        progressBar.setVisible(false);
                        lblFileSelezionato.setText("Nessun file selezionato");
                        fileDaDecifrare[0] = null;

                    }

                }

            };

            worker.execute();

        });

        gbc.gridx = 0; gbc.gridy = 0; panel.add(btnScegliFile, gbc);
        gbc.gridx = 1; panel.add(lblFileSelezionato, gbc);
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; panel.add(chkSafeDelete, gbc);
        gbc.gridy = 2; panel.add(btnDecifra, gbc);

        return panel;

    }

    private JPanel creaPannelloIdentita() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // --- SEZIONE SUPERIORE: GESTIONE MIA CHIAVE E PASSWORD ---
        JPanel topPanel = new JPanel(new GridLayout(3, 1, 10, 10));
        topPanel.setBorder(BorderFactory.createTitledBorder("Sicurezza e Identità"));

        JButton btnEsportaPubblica = new JButton("ESPORTA la mia Chiave Pubblica (.pub)");
        btnEsportaPubblica.addActionListener(e -> {
            JFileChooser saver = new JFileChooser();
            saver.setSelectedFile(new File("mia_chiave.pub"));
            if (saver.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    String b64Key = Base64.getEncoder().encodeToString(db.miaChiavePubblica.getEncoded());
                    Files.writeString(saver.getSelectedFile().toPath(), b64Key);
                    JOptionPane.showMessageDialog(this, "Chiave esportata correttamente!");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Errore: " + ex.getMessage());
                }
            }
        });

        JButton btnCambiaPassword = new JButton("CAMBIA Master Password");
        btnCambiaPassword.addActionListener(e -> mostraDialogoCambioPassword());

        JButton btnRigeneraIdentita = new JButton("RIGENERA Identità (RSA 4096)");
        btnRigeneraIdentita.setForeground(Color.RED);
        btnRigeneraIdentita.addActionListener(e -> {
            int conferma = JOptionPane.showConfirmDialog(this,
                    "ATTENZIONE: Rigenerando l'identità, tutti i file cifrati con la chiave attuale\n" +
                            "diventeranno IMPOSSIBILI da decifrare. Vuoi procedere?",
                    "Pericolo Perdita Dati", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

            if (conferma == JOptionPane.YES_OPTION) {
                try {
                    KeyPair kp = GestoreIdentita.generaNuovaIdentita();
                    db.miaChiavePrivata = kp.getPrivate();
                    db.miaChiavePubblica = kp.getPublic();
                    GestoreIdentita.salvaDatabase(db, masterPassword);
                    JOptionPane.showMessageDialog(this, "Nuova identità generata e salvata.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Errore: " + ex.getMessage());
                }
            }
        });

        topPanel.add(btnEsportaPubblica);
        topPanel.add(btnCambiaPassword);
        topPanel.add(btnRigeneraIdentita);

        // --- SEZIONE CENTRALE: RUBRICA (AGGIUNGI + LISTA) ---
        JPanel centerPanel = new JPanel(new GridLayout(1, 2, 15, 0));

        // 1. Sottopannello Aggiunta Contatto
        JPanel addPanel = new JPanel(new GridBagLayout());
        addPanel.setBorder(BorderFactory.createTitledBorder("Aggiungi Nuovo Contatto"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);

        JTextField txtNomeContatto = new JTextField(10);
        JLabel lblFileChiave = new JLabel("Nessun file selezionato");
        JButton btnCaricaChiave = new JButton("Scegli File .pub");
        final File[] fileChiaveContatto = {null};

        btnCaricaChiave.addActionListener(e -> {
            JFileChooser opener = new JFileChooser();
            if (opener.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                fileChiaveContatto[0] = opener.getSelectedFile();
                lblFileChiave.setText(fileChiaveContatto[0].getName());
            }
        });

        JButton btnSalvaContatto = new JButton("Salva in Rubrica");
        btnSalvaContatto.addActionListener(e -> {
            try {
                String nome = txtNomeContatto.getText().trim();
                if (nome.isEmpty() || fileChiaveContatto[0] == null) {
                    throw new IllegalArgumentException("Nome o File mancanti");
                }

                String b64Key = Files.readString(fileChiaveContatto[0].toPath()).replaceAll("\\s", "");
                byte[] keyBytes = Base64.getDecoder().decode(b64Key);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pubKey = kf.generatePublic(spec);

                db.rubricaContatti.put(nome, pubKey);
                GestoreIdentita.salvaDatabase(db, masterPassword);

                // Sincronizza le liste grafiche
                sincronizzaListeContatti();

                JOptionPane.showMessageDialog(this, "Contatto '" + nome + "' aggiunto!");
                txtNomeContatto.setText("");
                lblFileChiave.setText("Nessun file selezionato");
                fileChiaveContatto[0] = null;
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Errore: Chiave non valida.", "Errore", JOptionPane.ERROR_MESSAGE);
            }
        });

        gbc.gridx = 0; gbc.gridy = 0; addPanel.add(new JLabel("Nome:"), gbc);
        gbc.gridx = 1; addPanel.add(txtNomeContatto, gbc);
        gbc.gridx = 0; gbc.gridy = 1; addPanel.add(btnCaricaChiave, gbc);
        gbc.gridx = 1; addPanel.add(lblFileChiave, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; addPanel.add(btnSalvaContatto, gbc);

        // 2. Sottopannello Lista e Rimozione
        JPanel listPanel = new JPanel(new BorderLayout(10, 10));
        listPanel.setBorder(BorderFactory.createTitledBorder("Contatti Salvati"));

        listaGraficaContatti.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scrollPane = new JScrollPane(listaGraficaContatti);

        JButton btnEliminaContatto = new JButton("Elimina Contatto Selezionato");
        btnEliminaContatto.addActionListener(e -> {
            String selezionato = listaGraficaContatti.getSelectedValue();
            if (selezionato != null) {
                int confermi = JOptionPane.showConfirmDialog(this, "Eliminare " + selezionato + "?", "Conferma", JOptionPane.YES_NO_OPTION);
                if (confermi == JOptionPane.YES_OPTION) {
                    db.rubricaContatti.remove(selezionato);
                    try {
                        GestoreIdentita.salvaDatabase(db, masterPassword);
                        sincronizzaListeContatti();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(this, "Errore nel salvataggio.");
                    }
                }
            }
        });

        listPanel.add(scrollPane, BorderLayout.CENTER);
        listPanel.add(btnEliminaContatto, BorderLayout.SOUTH);

        // Unione pannelli centrali
        centerPanel.add(addPanel);
        centerPanel.add(listPanel);

        // Composizione finale
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(centerPanel, BorderLayout.CENTER);

        // Popola le liste al caricamento
        sincronizzaListeContatti();

        return panel;
    }


    private void mostraDialogoCambioPassword()
    {

        JPanel p = new JPanel(new GridLayout(3, 2, 5, 5));
        JPasswordField oldP = new JPasswordField();
        JPasswordField newP = new JPasswordField();
        JPasswordField confP = new JPasswordField();

        p.add(new JLabel("Password Attuale:")); p.add(oldP);
        p.add(new JLabel("Nuova Password:")); p.add(newP);
        p.add(new JLabel("Conferma Nuova:")); p.add(confP);

        int result = JOptionPane.showConfirmDialog(this, p, "Cambio Master Password", JOptionPane.OK_CANCEL_OPTION);

        if(result == JOptionPane.OK_OPTION)
        {

            char[] vecchia = oldP.getPassword();
            char[] nuova = newP.getPassword();
            char[] conferma = confP.getPassword();

            try
            {

                if(!java.util.Arrays.equals(vecchia, masterPassword))
                {

                    throw new Exception("La password attuale non è corretta.");

                }

                if(!java.util.Arrays.equals(nuova, conferma))
                {

                    throw new Exception("Le nuove password non coincidono.");

                }
                if(nuova.length < 8)
                {

                    throw new Exception("La nuova password è troppo debole (min 8 caratteri).");

                }

                GestoreIdentita.cambiaMasterPassword(db, vecchia, nuova, conferma, masterPassword);

                GestoreIdentita.pulisciPassword(masterPassword);
                masterPassword = nuova;

                JOptionPane.showMessageDialog(this, "Master Password aggiornata con successo!");

            }
            catch(Exception ex)
            {

                JOptionPane.showMessageDialog(this, "Errore: " + ex.getMessage(), "Errore", JOptionPane.ERROR_MESSAGE);

            }
            finally
            {

                GestoreIdentita.pulisciPassword(vecchia);
                GestoreIdentita.pulisciPassword(conferma);

            }

        }

    }

    private void sincronizzaListeContatti()
    {

        comboModel.removeAllElements();
        listModelContatti.clear();

        comboModel.addElement("Me Stesso (Mia Chiave)");

        for(String nome : db.rubricaContatti.keySet())
        {

            comboModel.addElement(nome);
            listModelContatti.addElement(nome);

        }

    }

    public static void main(String[] args) {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception ignored) {}
        SwingUtilities.invokeLater(() -> new AppGUI().setVisible(true));
    }
}