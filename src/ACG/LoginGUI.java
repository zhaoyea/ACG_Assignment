package ACG;

import Encryption.UserAuthentication;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by tanzh on 13/02/2017.
 */
public class LoginGUI {
    private JTextField IPField;
    private JTextField PortField;
    private JTextField Username;
    private JPasswordField Password;
    private JButton registerButton;
    private JButton loginButton;
    private JLabel UserLabel;
    private JLabel PasswordLabel;
    private JButton cancelButton;
    private JPanel loginPanel;
    private JFrame init;

    public LoginGUI(JFrame init) {
        this.init = init;
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                init.setContentPane(new RegisterGUI().registerPanel);
                init.pack();
                init.setVisible(true);
        }
        });

        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String username = Username.getText();
                String password = Password.getText();
                try {
                    if ((UserAuthentication.VerfiyUser(username, password)) == 1) {
                        init.setContentPane(new ClientGUI("localhost", 1500, username));
                        init.pack();
                        init.setVisible(true);
                    } else {
                        JOptionPane.showMessageDialog(null, "Error: Username or Password wrong!\nPlease try again!");
                        System.exit(0);
                    }
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }
        });
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
