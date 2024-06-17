package pw.evelynn.pincracker;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import java.awt.*;
import java.security.MessageDigest;
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;

public class Main {

    private JTextField keyField;
    private JTextField saltField;
    private JTextField passwordField;
    private JTextField passEndField;
    private JLabel statusLabel;
    private AtomicBoolean stopFlag;

    public Main() {
        Security.addProvider(new BouncyCastleProvider());
        createUI();
    }

    private void createUI() {
        JFrame frame = new JFrame("iOS 7 to 11 passcode cracker by Evelynn");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        JPanel panel = new JPanel(new GridLayout(6, 2));
        frame.add(panel);

        panel.add(new JLabel("RestrictionsPasswordKey:"));
        keyField = new JTextField(33);
        panel.add(keyField);

        panel.add(new JLabel("RestrictionsPasswordSalt:"));
        saltField = new JTextField(14);
        panel.add(saltField);

        panel.add(new JLabel("Starting Passcode:"));
        passwordField = new JTextField("0000", 14);
        panel.add(passwordField);

        panel.add(new JLabel("Last Search Code:"));
        passEndField = new JTextField("9999", 14);
        panel.add(passEndField);

        JButton testButton = new JButton("Test Single Code");
        testButton.addActionListener(e -> testCode());
        panel.add(testButton);

        JButton startButton = new JButton("Start Searching");
        startButton.addActionListener(e -> startSearching());
        panel.add(startButton);

        JButton stopButton = new JButton("Stop Searching");
        stopButton.addActionListener(e -> stopSearching());
        panel.add(stopButton);

        statusLabel = new JLabel();
        panel.add(statusLabel);

        frame.setVisible(true);
    }

    private void startSearching() {
        stopFlag = new AtomicBoolean(false);
        new Thread(this::searchCode).start();
    }

    private void stopSearching() {
        if (stopFlag != null) {
            stopFlag.set(true);
        }
    }

    private void testCode() {
        stopFlag = new AtomicBoolean(true);
        searchCode();
    }

    private void searchCode() {
        try {
            String keyBase64 = keyField.getText();
            byte[] key = Base64.decode(keyBase64);
            String saltBase64 = saltField.getText();
            byte[] salt = Base64.decode(saltBase64);

            int startCode = Integer.parseInt(passwordField.getText());
            int endCode = Integer.parseInt(passEndField.getText());

            for (int i = startCode; i <= endCode && !stopFlag.get(); i++) {
                String pass = String.format("%04d", i);
                byte[] generatedKey = generatePBKDF2Key(pass.toCharArray(), salt);

                if (MessageDigest.isEqual(key, generatedKey)) {
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("FOUND! Passcode: " + pass);
                        JOptionPane.showMessageDialog(null, "The passcode is: " + pass);
                    });
                    return;
                }
            }

            SwingUtilities.invokeLater(() -> statusLabel.setText("Completed search without finding the passcode"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] generatePBKDF2Key(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 160);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC");
        return factory.generateSecret(spec).getEncoded();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Main::new);
    }
}
