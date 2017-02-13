package ACG;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Created by tanzh on 12/02/2017.
 */
public class DemoClientGUI {

    private JTextField Username;
    private JButton cancelButton;
    private JButton enterButton;
    private JPasswordField PasswordField;
    private JPanel panel;
    private JFrame init;

    public DemoClientGUI(JFrame init) {
        this.init = init;
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });
        enterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                init.setContentPane(new ClientGUI("localhost", 1500));
                init.pack();
                init.setVisible(true);
            }
        });
        Username.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        PasswordField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
    }
    public static void main(String[] args) {
        JFrame frame = new JFrame("DemoClientGUI");
        frame.setContentPane(new DemoClientGUI(frame).panel);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }
}
