import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import javax.net.ssl.*;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client {

    // for I/O
    private ObjectInputStream sInput;        // to read from the socket
    private ObjectOutputStream sOutput;        // to write on the socket
    private SSLSocket sslSocket;

    // if I use a GUI or not
    private ClientGUI cg;

    // the server, the port and the username
    private String server, username;
    private int port;

    /*
     *  Constructor called by console mode
     *  server: the server address
     *  port: the port number
     *  username: the username
     */
    Client(String server, int port, String username) {
        // which calls the common constructor with the GUI set to null
        this(server, port, username, null);
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

    //////////////////////////////////
    ///// CREATE THE SSL CONTEXT /////
    //////////////////////////////////
    private SSLContext createSSLContext() {
        try {
            /////////////////////////////////////////
            ///// LOAD THE CLIENT'S PRIVATE KEY /////
            /////////////////////////////////////////
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("src/SSL Cert/mykeystore.jks"), "12345678".toCharArray());
            ///////////////////////////////////
            ///// CREATE THE KEY MANAGER /////
            //////////////////////////////////
            KeyManagerFactory clientKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            clientKeyManagerFactory.init(keyStore, "12345678".toCharArray());
            KeyManager[] km = clientKeyManagerFactory.getKeyManagers();

            ////////////////////////////////////
            ///// CREATE THE TRUST MANAGER /////
            ////////////////////////////////////
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            ////////////////////////////////////////////////////
            ///// USE THE KEYS TO INITILISE THE SSLCONTEXT /////
            ////////////////////////////////////////////////////
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(km, tm, SecureRandom.getInstance("SHA1PRNG"));

            return sslContext;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public X509Certificate getCACertificate() throws Exception {
        //Declaration of variables to be used
        String keystoreFile = "src/SSL Cert/mykeystore.jks";
        String caAlias = "ca";
        String keyStorePwd = "12345678";

        //Read from the keystore
        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, keyStorePwd.toCharArray());
        X509Certificate caCert = (X509Certificate) keyStore.getCertificate(caAlias);

        return caCert;

    }

    public void checkServerCert(X509Certificate cert) throws Exception {
        if (cert == null) {
            throw new IllegalArgumentException("Null or zero-length certificate chain");
        }
        X509Certificate caCert = getCACertificate();

        //Check if certificate send if your CA's
        if (!cert.equals(caCert)) {
            try {
                cert.verify(caCert.getPublicKey());
            } catch (Exception e) {
                throw new CertificateException("Certificate not trusted", e);
            }
        }
        //If we end here certificate is trusted. Check if it has expired.
        try{
            cert.checkValidity();
        }
        catch(Exception e){
            throw new CertificateException("Certificate not trusted. It has expired",e);
        }
    }

    /*
     * To start the dialog
     */
    public boolean start() {
        //////////////////////////////////
        ///// CREATE THE SSLCONTEXT /////
        ///// AND WAIT CONNECTION  //////
        ////////////////////////////////
        SSLContext sslContext = createSSLContext();
        try {
            /////////////////////////////
            /// Create socket factory ///
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            sslSocket = (SSLSocket) sslSocketFactory.createSocket(server, port);

            // create output first
            sOutput = new ObjectOutputStream(sslSocket.getOutputStream());
            sInput = new ObjectInputStream(sslSocket.getInputStream());

            //Start of Certificate verification
            sOutput.writeObject("Hello Server");
            String serverMsg = (String) sInput.readObject();
            X509Certificate serverCert = (X509Certificate) sInput.readObject();

            if (serverMsg.contains("Hello Client")) {
                checkServerCert(serverCert);
                sslSocket.startHandshake();
                SSLSession sslSession = sslSocket.getSession();
                System.out.println("SSL Session: ");
                System.out.println("\t" + sslSession.getCipherSuite());
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

        String msg = "Connection accepted " + sslSocket.getInetAddress() + ":" + sslSocket.getPort();
        display(msg);

        // Send our username to the server this is the only message that we
        // will send as a String. All other messages will be ChatMessage objects
        try {
            // Once establish connection with the server, client will send a msg to the server before he logs in
            sOutput.writeObject(username);

        } catch (IOException eIO) {
            display("Exception doing login : " + eIO);
            disconnect();
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
            cg.append(msg + "\n");        // append to the ClientGUI JTextArea (or whatever)
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
     * To start the Client in console mode use one of the following command
     * > java Client
     * > java Client username
     * > java Client username portNumber
     * > java Client username portNumber serverAddress
     * at the console prompt
     * If the portNumber is not specified 1500 is used
     * If the serverAddress is not specified "localHost" is used
     * If the username is not specified "Anonymous" is used
     * > java Client
     * is equivalent to
     * > java Client Anonymous 1500 localhost
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
            // > javac Client username portNumber serverAddr
            case 3:
                serverAddress = args[2];
                // > javac Client username portNumber
            case 2:
                try {
                    portNumber = Integer.parseInt(args[1]);
                } catch (Exception e) {
                    System.out.println("Invalid port number.");
                    System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
                    return;
                }
                // > javac Client username
            case 1:
                userName = args[0];
                // > java Client
            case 0:
                break;
            // invalid number of arguments
            default:
                System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
                return;
        }
        // create the Client object
        Client client = new Client(serverAddress, portNumber, userName);
        // test if we can start the connection to the Server
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
                    display("Server has close the connection: " + e);
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
}
