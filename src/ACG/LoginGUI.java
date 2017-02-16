package ACG;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;

import static ACG.Client.encryption;

/**
 * Created by tanzh on 13/02/2017.
 */
public class LoginGUI {
    //private final JFrame init;
    private JTextField IPField;
    private JTextField Username;
    private JPasswordField Password;
    private JButton register;
    private JPanel loginPanel;
    private JTextField PortField;
    private JTextField message;
    private JButton sendButton;
    private JScrollBar scrollBar1;
    private JButton logout;
    private JButton whoIsIn;
    private JTextArea ta;
    public JButton login;
    private Client client;
    private boolean connected;
    private SecretKey aesKey;
    Cipher cipherUtil;

    String username = Username.getText();
    String password = Password.getText();
    String serverAddr = IPField.getText();
    int serverPort = Integer.parseInt(PortField.getText());


    public LoginGUI() {
        //this.init = init;
        login.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loginActionPerformed(e);
            }
        });

        register.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                registerActionPerformed(e);
            }
        });
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendActionPerformed(e);
            }
        });
        logout.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logoutActionPerformed(e);
            }
        });

        whoIsIn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                whoIsInActionPerformed(e);
            }
        });
    }

    private void loginActionPerformed(ActionEvent e) {
        if (!serverAddr.isEmpty() && !(PortField.getText().isEmpty()) && !Username.getText().isEmpty() && !Password.getText().isEmpty()) {
            username = Username.getText();
            password = Password.getText();
            client = new Client(serverAddr, serverPort, username, password, this, true);

            // test if we can start the ACG.Client
            if (!client.start())
                return;

            IPField.setEnabled(false);
            PortField.setEnabled(false);
            login.setEnabled(false);
            Username.setEnabled(false);
            Password.setEnabled(false);
            register.setEnabled(false);
            ta.setEnabled(true);
            whoIsIn.setEnabled(true);
            logout.setEnabled(true);
            message.setEnabled(true);
            sendButton.setEnabled(true);

        } else {
            return;
        }
    }

    public void registerActionPerformed(ActionEvent e) {
        if (!serverAddr.isEmpty() && !(PortField.getText().isEmpty()) && !Username.getText().isEmpty() && !Password.getText().isEmpty()) {
            username = Username.getText();
            password = Password.getText();
            client = new Client(serverAddr, serverPort, username, password, this, false);
            // test if we can start the ACG.Client
            if (!client.start())
                return;

            IPField.setEnabled(false);
            PortField.setEnabled(false);
            login.setEnabled(false);
            Username.setEnabled(false);
            Password.setEnabled(false);
            register.setEnabled(false);
            ta.setEnabled(true);
            whoIsIn.setEnabled(true);
            logout.setEnabled(true);
            message.setEnabled(true);
            sendButton.setEnabled(true);
        } else {
            return;
        }
    }


    public void sendActionPerformed(ActionEvent e) {
        if (!message.getText().isEmpty()) {
            try {
                Cipher cipherUtil = Cipher.getInstance("AES/ECB/PKCS5Padding");
                //String encryptedMsg = cryptoUtils.encrypt(message.getText(), aesKey, cipherUtil);
                String encryptedMsg = encryption(message.getText(), cipherUtil);
                client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, encryptedMsg));
                message.setText("");
                return;
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            } catch (NoSuchPaddingException e1) {
                e1.printStackTrace();
            }
        }
    }

    public void whoIsInActionPerformed(ActionEvent e) {
        client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));
        return;
    }

    private void logoutActionPerformed(ActionEvent e) {
        client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, ""));
        return;
    }

    // called by the ACG.Client to append text in the TextArea
    void append(String str) {
        ta.append(str + "\n");
        ta.setCaretPosition(ta.getText().length() - 1);
    }

    // called by the GUI is the connection failed
    // we reset our buttons, label, textfield
    void connectionFailed() {
        connected = false;
        System.exit(0);
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("LoginGUI");
        frame.setContentPane(new LoginGUI().loginPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }

    private SecretKey getKey() {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            aesKey = keyGenerator.generateKey();
            cipherUtil = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return aesKey;
    }
}
