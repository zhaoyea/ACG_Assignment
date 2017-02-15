package ACG;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by tanzh on 13/02/2017.
 */
public class LoginGUI {
    private final JFrame init;
    private JTextField IPField;
    private JTextField Username;
    private JPasswordField Password;
    private JButton register;
    private JPanel loginPanel;
    private JButton connectButton;
    private JTextField PortField;
    private JTextField message;
    private JButton sendButton;
    private JList userList;
    private JScrollBar scrollBar1;
    private JButton logout;
    private JButton whoIsIn;
    private JTextArea ta;
    private Client client;
    private boolean connected;

    String username = Username.getText();
    String password = Password.getText();
    String serverAddr = IPField.getText();
    int serverPort = Integer.parseInt(PortField.getText());


    public LoginGUI(JFrame init) {
        this.init = init;
        connectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                connectActionPerformed(e);
            }
        });

        register.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                init.setContentPane(new RegisterGUI().registerPanel);
                init.pack();
                init.setVisible(true);
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

    private void connectActionPerformed(ActionEvent e) {
        if (!serverAddr.isEmpty() && !(PortField.getText().isEmpty()) && !Username.getText().isEmpty() && !Password.getText().isEmpty()) {
            username = Username.getText();
            password = Password.getText();
            client = new Client(serverAddr, serverPort, username, password, this);
            // test if we can start the ACG.Client
            if (!client.start())
                return;

            connected = true;
            IPField.setEnabled(false);
            PortField.setEnabled(false);
            connectButton.setEnabled(false);
            Username.setEnabled(false);
            Password.setEnabled(false);
            register.setEnabled(false);
            logout.setEnabled(true);
            message.setEnabled(true);
            sendButton.setEnabled(true);
        } else {
            return;
        }
    }

    public void sendActionPerformed(ActionEvent e) {
        if (!message.getText().isEmpty()) {
            client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, message.getText()));
            message.setText("");
            return;
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
        ta.append("\n" + str);
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
        frame.setContentPane(new LoginGUI(frame).loginPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
