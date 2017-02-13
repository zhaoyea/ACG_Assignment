package ACG;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by tanzh on 13/02/2017.
 */
public class RegisterGUI extends Container {
    private JTextField ServerIPTextField;
    private JTextField portTextField;
    private JTextField newUsername;
    private JPasswordField newPasswordField1;
    private JPasswordField newPasswordField2;
    public JPanel registerPanel;
    private JButton registerButton;
    private JButton cancelButton;

    public RegisterGUI() {
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("RegisterGUI");
        frame.setContentPane(new RegisterGUI().registerPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }


}
