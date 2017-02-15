package ACG;

import javax.swing.*;
import java.awt.*;

/**
 * Created by tanzh on 15/02/2017.
 */
public class RegisterGUI extends Container {
    private JTextField IPField;
    private JTextField portField;
    private JTextField newUser;
    private JPasswordField newPwd;
    private JPasswordField confirmPwd;
    private JButton Register;
    private JButton connect;
    public JPanel registerPanel;

    public static void main(String[] args) {
        JFrame frame = new JFrame("RegisterGUI");
        frame.setContentPane(new RegisterGUI().registerPanel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }
}
