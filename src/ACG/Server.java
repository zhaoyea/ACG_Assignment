package ACG;

import Encryption.HashUtils;
import Encryption.SSLUtils;
import Encryption.UserAuthentication;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
    // a unique ID for each connection
    private static int uniqueId;
    // an ArrayList to keep the list of the ACG.Client
    private ArrayList<ClientThread> al;
    // if I am in a GUI
    private ServerGUI sg;
    // to display time
    private SimpleDateFormat sdf;
    // the port number to listen for connection
    private int port;
    // the boolean that will be turned of to stop the server
    private boolean keepGoing;

    private static final String USERS_FILE_NAME = "src/Users/users.txt";

    /*
     *  server constructor that receive the port to listen to for connection as parameter
     *  in console
     */
    public Server(int port) {
        this(port, null);
    }

    public Server(int port, ServerGUI sg) {
        // GUI or not
        this.sg = sg;
        // the port
        this.port = port;
        // to display hh:mm:ss
        sdf = new SimpleDateFormat("HH:mm:ss");
        // ArrayList for the ACG.Client list
        al = new ArrayList<ClientThread>();
    }


    public void start() throws Exception {
        keepGoing = true;

        //////////////////////////////////
        ///// CREATE THE SSLCONTEXT /////
        ///// AND WAIT CONNECTION  //////
        ////////////////////////////////
        SSLContext sslContext = SSLUtils.createSSLContext();
        try {
            // the socket used by the server
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

            // infinite loop to wait for connections
            while (keepGoing) {
                // format message saying we are waiting
                display("ACG.Server waiting for Clients on port " + port + ".");

                //accept connection
                SSLSocket sslsocket = (SSLSocket) sslServerSocket.accept();

                // if I was asked to stop
                if (!keepGoing)
                    break;
                ClientThread t = new ClientThread(sslsocket);  // make a thread of it
                al.add(t);                                    // save it in the ArrayList
                t.start();
            }
            // I was asked to stop
            try {
                sslServerSocket.close();
                for (int i = 0; i < al.size(); ++i) {
                    ClientThread tc = al.get(i);
                    try {
                        tc.sInput.close();
                        tc.sOutput.close();
                        tc.sslsocket.close();
                    } catch (IOException ioE) {
                        // not much I can do
                    }
                }
            } catch (Exception e) {
                display("Exception closing the server and clients: " + e);
            }
        }
        // something went bad
        catch (IOException e) {
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
            display(msg);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }

    /*
     * For the GUI to stop the server
     */
    protected void stop() {
        keepGoing = false;
        // connect to myself as ACG.Client to exit statement
        // Socket socket = serverSocket.accept();
        try {
            new Socket("localhost", port);
        } catch (Exception e) {
            // nothing I can really do
        }
    }

    /*
     * Display an event (not a message) to the console or the GUI
     */
    private void display(String msg) {
        String time = sdf.format(new Date()) + " " + msg;
        if (sg == null)
            System.out.println(time);
        else
            sg.appendEvent(time + "\n");
    }

    /*
     *  to broadcast a message to all Clients
     */
    private synchronized void broadcast(String message) {
        // add HH:mm:ss and \n to the message
        String time = sdf.format(new Date());
        String messageLf = time + " " + message + "\n";
        // display message on console or GUI
        if (sg == null)
            System.out.print(messageLf);
        else
            sg.appendRoom(messageLf);     // append in the room window

        // we loop in reverse order in case we would have to remove a ACG.Client
        // because it has disconnected
        for (int i = al.size(); --i >= 0; ) {
            ClientThread ct = al.get(i);
            // try to write to the ACG.Client if it fails remove it from the list
            if (!ct.writeMsg(messageLf)) {
                al.remove(i);
                display("Disconnected ACG.Client " + ct.username + " removed from list.");
            }
        }
    }

    // for a client who logoff using the LOGOUT message
    synchronized void remove(int id) {
        // scan the array list until we found the Id
        for (int i = 0; i < al.size(); ++i) {
            ClientThread ct = al.get(i);
            // found it
            if (ct.id == id) {
                al.remove(i);
                return;
            }
        }
    }


    /**
     * One instance of this thread will run for each client
     */
    class ClientThread extends Thread {
        // the socket where to listen/talk
        SSLSocket sslsocket;
        ObjectInputStream sInput;
        ObjectOutputStream sOutput;
        // my unique id (easier for deconnection)
        int id;
        // the Username of the ACG.Client
        String username;
        // the only type of message a will receive
        ChatMessage cm;
        // the date I connect
        String date;
        String msg;

        // Constructor
        ClientThread(SSLSocket sslsocket) throws Exception {
            // a unique id
            id = ++uniqueId;
            this.sslsocket = sslsocket;
            /* Creating both Data Stream */
            System.out.println("Thread trying to create Object Input/Output Streams");
            try {
                // create output first
                sOutput = new ObjectOutputStream(sslsocket.getOutputStream());
                sInput = new ObjectInputStream(sslsocket.getInputStream());

                String clientMsg = (String) sInput.readObject();
                X509Certificate serverCert = SSLUtils.getServerCertificate();
                System.out.println("*************************************");
                System.out.println(clientMsg);
                if (clientMsg.equals("Hello ACG.Server")) {
                    sOutput.writeObject("Hello ACG.Client\nThis is my Certificate: ");
                    sOutput.writeObject(serverCert);

                    if (((String) sInput.readObject()).contains("Trusted ACG.Server")) {
                        /*
                        byte [] encryptedUserName = (byte[]) sInput.readObject();
                        byte [] encryptedPwd = (byte[]) sInput.readObject();
                        System.out.println(asHex(encryptedUserName));
                        System.out.println(asHex(encryptedPwd));
                        */
                        PrivateKey serverPrivateKey = SSLUtils.getPrivateKey();
                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                        String option = (String) sInput.readObject();
                        System.out.println(option);
                        byte[] decryptedUserName = cipher.doFinal((byte[]) sInput.readObject());
                        byte[] decryptedPwd = cipher.doFinal((byte[]) sInput.readObject());
                        System.out.println("*************************************");
                        System.out.println("Decrypted Username:" + new String(decryptedUserName));
                        System.out.println("Decrypted Password:" + new String(decryptedPwd));
                        System.out.println("*************************************");

                        String decryptedUsernameAsString = new String(decryptedUserName, "UTF-8");
                        String decryptedPasswordAsString = new String(decryptedPwd, "UTF-8");

                        if (option.equals("1")) {
                            /////////////////////
                            // Register a User //
                            /////////////////////
                            UserAuthentication.RegisterUserVerfiy(decryptedUsernameAsString, decryptedPasswordAsString);
                            byte[] salt = HashUtils.getSalt();
                            String hashPwd = HashUtils.asHex(HashUtils.hashPassword(decryptedPasswordAsString.toCharArray(), salt, 1000, 512));
                            Files.write(Paths.get(USERS_FILE_NAME), "".getBytes(), StandardOpenOption.APPEND);
                            Files.write(Paths.get(USERS_FILE_NAME), (decryptedUsernameAsString + "::" + asHex(salt) + ":" + hashPwd + "\n").getBytes(), StandardOpenOption.APPEND);
                            System.out.println("*************************************");
                            System.out.println("Users: " + decryptedUsernameAsString + " created. Password stored in " + USERS_FILE_NAME);
                            System.out.println("*************************************");

                        } else if (option.equals("2")) {
                            ///////////////////////////
                            // Authenticating a User //
                            ///////////////////////////
                            UserAuthentication.VerfiyUser(decryptedUsernameAsString, decryptedPasswordAsString);

                        } else {
                            System.out.println("*************************************");
                            System.out.println("Error: Unable to compute the option");
                            sslsocket.close();
                        }
                    } else {
                        System.out.println("Failed: ACG.Client never send Hello text");
                        sslsocket.close();
                    }
                } else {
                    System.out.println("Failed: ACG.Client never send Hello text");
                    sslsocket.close();
                }
                // read the username
                username = (String) sInput.readObject();
                display(username + " just connected.");
            } catch (IOException e) {
                display("Exception creating new Input/output Streams: " + e);
                return;
            }
            // have to catch ClassNotFoundException
            // but I read a String, I am sure it will work
            catch (ClassNotFoundException e) {
            }
            date = new Date().toString() + "\n";
        }

        // what will run forever
        public void run() {
            // to loop until LOGOUT
            boolean keepGoing = true;
            while (keepGoing) {
                // read a String (which is an object)
                try {
                    cm = (ChatMessage) sInput.readObject();
                } catch (IOException e) {
                    display(username + " Exception reading Streams: " + e);
                    break;
                } catch (ClassNotFoundException e2) {
                    break;
                }
                // the messaage part of the ACG.ChatMessage
                String message = cm.getMessage();

                // Switch on the type of message receive
                switch (cm.getType()) {

                    case ChatMessage.MESSAGE:
                        broadcast(username + ": " + message);
                        break;
                    case ChatMessage.LOGOUT:
                        display(username + " disconnected with a LOGOUT message.");
                        keepGoing = false;
                        break;
                    case ChatMessage.WHOISIN:
                        writeMsg("List of the users connected at " + sdf.format(new Date()) + "\n");
                        // scan al the users connected
                        for (int i = 0; i < al.size(); ++i) {
                            ClientThread ct = al.get(i);
                            writeMsg((i + 1) + ") " + ct.username + " since " + ct.date);
                        }
                        break;
                }
            }
            // remove myself from the arrayList containing the list of the
            // connected Clients
            remove(id);
            close();
        }

        // try to close everything
        private void close() {
            // try to close the connection
            try {
                if (sOutput != null) sOutput.close();
            } catch (Exception e) {
            }
            try {
                if (sInput != null) sInput.close();
            } catch (Exception e) {
            }
            ;
            try {
                if (sslsocket != null) sslsocket.close();
            } catch (Exception e) {
            }
        }

        /*
         * Write a String to the ACG.Client output stream
         */
        private boolean writeMsg(String msg) {
            // if ACG.Client is still connected send the message to it
            if (!sslsocket.isConnected()) {
                close();
                return false;
            }
            // write the message to the stream
            try {
                sOutput.writeObject(msg);
            }
            // if an error occurs, do not abort just inform the user
            catch (IOException e) {
                display("Error sending message to " + username);
                display(e.toString());
            }
            return true;
        }
    }

    /*
     *  To run as a console application just open a console window and:
     * > java ACG.Server
     * > java ACG.Server portNumber
     * If the port number is not specified 1500 is used
     */
    public static void main(String[] args) throws Exception {
        // start server on port 1500 unless a PortNumber is specified
        int portNumber = 1500;
        switch (args.length) {
            case 1:
                try {
                    portNumber = Integer.parseInt(args[0]);
                } catch (Exception e) {
                    System.out.println("Invalid port number.");
                    System.out.println("Usage is: > java ACG.Server [portNumber]");
                    return;
                }
            case 0:
                break;
            default:
                System.out.println("Usage is: > java ACG.Server [portNumber]");
                return;

        }
        // create a server object and start it
        Server server = new Server(portNumber);
        server.start();
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
