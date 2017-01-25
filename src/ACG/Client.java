package ACG;

import Encryption.encrypt;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/*
 * The ACG.Client that can be run both as a console or a GUI
 */
public class Client {

    // for I/O
    private ObjectInputStream sInput;        // to read from the socket
    private ObjectOutputStream sOutput;        // to write on the socket
    private SSLSocket sslSocket;

    // if I use a GUI or not
    private ClientGUI cg;

    // the server, the port and the username
    private String server, username, password, option;
    private int port;

    /*
     *  Constructor called by console mode
     *  server: the server address
     *  port: the port number
     *  username: the username
     */
    Client(String server, int port, String username) {
        // which calls the common constructor with the GUI set to null
        this(server, port, username,null);
    }

    /*
     * Constructor call when used from a GUI
     * in console mode the ClienGUI parameter is null
     */
    Client(String server, int port, String username, ClientGUI cg) {
        this.server = server;
        this.port = port;
        this.username = username;
        // save if we are in GUI mode or not
        this.cg = cg;
    }


    /*
     * To start the dialog
     */
    public boolean start() {
        //////////////////////////////////
        ///// CREATE THE SSLCONTEXT /////
        ///// AND WAIT CONNECTION  //////
        ////////////////////////////////
        SSLContext sslContext = encrypt.createSSLContext();
        try {
            /////////////////////////////
            /// Create socket factory ///
            /////////////////////////////
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            sslSocket = (SSLSocket) sslSocketFactory.createSocket(server, port);

            // create output first
            sOutput = new ObjectOutputStream(sslSocket.getOutputStream());
            sInput = new ObjectInputStream(sslSocket.getInputStream());

            ////////////////////////////////////////////////
            /// Start of ACG.Server Certificate verification ///
            ////////////////////////////////////////////////
            sOutput.writeObject("Hello ACG.Server");
            String serverMsg = (String) sInput.readObject();
            //Read the Certificate send from ACG.Server
            X509Certificate serverCert = (X509Certificate) sInput.readObject();

            if (serverMsg.contains("Hello ACG.Client")) {
                //Checking of ACG.Server Certificate
                encrypt.checkServerCert(serverCert);
                //Start the ssl handshake if true
                sslSocket.startHandshake();
                sOutput.writeObject("Trusted ACG.Server");
                SSLSession sslSession = sslSocket.getSession();
                System.out.println("SSL Session: ");
                System.out.println("\t" + sslSession.getCipherSuite());


                String msg = "Connection accepted " + sslSocket.getInetAddress() + ":" + sslSocket.getPort();
                display(msg);

                Scanner in = new Scanner(System.in);
                System.out.println("\n************ Start of Program ************");
                System.out.println("Home Page:\n1. Register\n2. Login\nChoose 1 option: ");
                option = in.nextLine();
                //write option to Server
                sOutput.writeObject(option);
                if (option.equals("1") || option.equals("l") || option.equals("L") || option.equals("Login") || option.equals("login")) {
                    System.out.println("**********************************");
                    System.out.println("** Welcome to the Register Page **");
                    System.out.println("**********************************");
                    System.out.println("New Username:");
                    username = in.nextLine();
                    System.out.println("New Password:");
                    password = in.nextLine();
                } else if (option.equals("2") || option.equals("r") || option.equals("R") || option.equals("Register") || option.equals("register")) {
                    System.out.println("********************************");
                    System.out.println("** Welcome to the Login Page **");
                    System.out.println("********************************");
                    System.out.println("Username: ");
                    username = in.nextLine();
                    System.out.println("Password: ");
                    password = in.nextLine();
                } else {
                    System.out.println("Invalid Input");
                    sslSocket.close();
                }
                //After handshake starts, ask User to login
                //http://www.programmingsimplified.com/java/source-code/java-program-take-input-from-user

                //Grab the server public key
                PublicKey serverPub = serverCert.getPublicKey();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, serverPub);
                //Encrypt the username and password
                byte[] PlainUserName = username.getBytes("UTF8");
                byte[] PlainPwd = password.getBytes("UTF8");
                byte[] encryptedUserName = cipher.doFinal(PlainUserName);
                byte[] encryptedPwd = cipher.doFinal(PlainPwd);
                /*
                // Print the encryptedUserName
                System.out.println("\n\nUsername: ");
                System.out.println(asHex(encryptedUserName));
                // Print the encryptedUserName
                System.out.println("\n\nPassword: ");
                System.out.println(asHex(encryptedPwd));
                */

                //Send the encrypted credentials to the server
                sOutput.writeObject(encryptedUserName);
                sOutput.writeObject(encryptedPwd);

                // Send our username to the server this is the only message that we
                // will send as a String. All other messages will be ACG.ChatMessage objects
                try {
                    sOutput.writeObject(username);
                } catch (IOException eIO) {
                    display("Exception doing login : " + eIO);
                    disconnect();
                    return false;
                }

            } else {
                System.out.println("SSL Certificate verification fail");
                sslSocket.close();
            }
        }
        // if it failed not much I can so
        catch (Exception ec) {
            display("Error connectiong to server:" + ec);
            return false;
        }


        // creates the Thread to listen from the server
        new ListenFromServer().start();
        // success we inform the caller that it worked
        return true;
    }

	/*
     * To send a message to the console or the GUI
	 */

    private void display(String msg) {
        if (cg == null)
            System.out.println(msg);      // println in console mode
        else
            cg.append(msg + "\n");        // append to the ACG.ClientGUI JTextArea (or whatever)
    }

    /*
     * To send a message to the server
     */
    void sendMessage(ChatMessage msg) {
        try {
            sOutput.writeObject(msg);
        } catch (IOException e) {
            display("Exception writing to server: " + e);
        }
    }

    /*
     * When something goes wrong
     * Close the Input/Output streams and disconnect not much to do in the catch clause
     */
    private void disconnect() {
        try {
            if (sInput != null) sInput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (sOutput != null) sOutput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (sslSocket != null) sslSocket.close();
        } catch (Exception e) {
        } // not much else I can do

        // inform the GUI
        if (cg != null)
            cg.connectionFailed();

    }

    /*
     * To start the ACG.Client in console mode use one of the following command
     * > java ACG.Client
     * > java ACG.Client username
     * > java ACG.Client username portNumber
     * > java ACG.Client username portNumber serverAddress
     * at the console prompt
     * If the portNumber is not specified 1500 is used
     * If the serverAddress is not specified "localHost" is used
     * If the username is not specified "Anonymous" is used
     * > java ACG.Client
     * is equivalent to
     * > java ACG.Client Anonymous 1500 localhost
     * are eqquivalent
     *
     * In console mode, if an error occurs the program simply stops
     * when a GUI id used, the GUI is informed of the disconnection
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        // default values
        int portNumber = 1500;
        String serverAddress = "localhost";
        String userName = "Anonymous";

        // depending of the number of arguments provided we fall through
        switch (args.length) {
            // > javac ACG.Client username portNumber serverAddr
            case 3:
                serverAddress = args[2];
                // > javac ACG.Client username portNumber
            case 2:
                try {
                    portNumber = Integer.parseInt(args[1]);
                } catch (Exception e) {
                    System.out.println("Invalid port number.");
                    System.out.println("Usage is: > java ACG.Client [username] [portNumber] [serverAddress]");
                    return;
                }
                // > javac ACG.Client username
            case 1:
                userName = args[0];
                // > java ACG.Client
            case 0:
                break;
            // invalid number of arguments
            default:
                System.out.println("Usage is: > java ACG.Client [username] [portNumber] {serverAddress]");
                return;
        }
        // create the ACG.Client object
        Client client = new Client(serverAddress, portNumber, userName);
        // test if we can start the connection to the ACG.Server
        // if it failed nothing we can do
        if (!client.start())
            return;
        //else
        //   createKey();

        // wait for messages from user
        Scanner scan = new Scanner(System.in);
        // loop forever for message from the user
        while (true) {
            System.out.print("> ");
            // read message from user
            String msg = scan.nextLine();
            // logout if message is LOGOUT
            if (msg.equalsIgnoreCase("LOGOUT")) {
                client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, ""));
                // break to do the disconnect
                break;
            }
            // message WhoIsIn
            else if (msg.equalsIgnoreCase("WHOISIN")) {
                client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));
            } else {                // default to ordinary message
                client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg));
            }
        }
        // done disconnect
        client.disconnect();
    }

    /*
     * a class that waits for the message from the server and append them to the JTextArea
     * if we have a GUI or simply System.out.println() it in console mode
     */
    class ListenFromServer extends Thread {

        public void run() {
            while (true) {
                try {
                    String msg = (String) sInput.readObject();
                    // if console mode print the message and add back the prompt
                    if (cg == null) {
                        System.out.println(msg);
                        System.out.print("> ");
                    } else {
                        cg.append(msg);
                    }
                } catch (IOException e) {
                    display("ACG.Server has close the connection: " + e);
                    if (cg != null)
                        cg.connectionFailed();
                    break;
                }
                // can't happen with a String object but need the catch anyhow
                catch (ClassNotFoundException e2) {
                }
            }
        }
    }
    public static String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
    }
}
