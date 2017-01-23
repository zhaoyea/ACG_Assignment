import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.crypto.Cipher;
import javax.net.ssl.*;

/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;

	//Declaration of variables to be used
	String keystoreFile = "src/SSL Cert/mykeystore.jks";
	String serverAlias = "server_signed";
	String keyStorePwd = "12345678";


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
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
	}

	//////////////////////////////////
	///// CREATE THE SSL CONTEXT /////
	//////////////////////////////////
	public SSLContext createSSLContext() {
		try {

			/////////////////////////////////////////
			///// LOAD THE SERVER'S PRIVATE KEY /////
			/////////////////////////////////////////
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream("src/SSL Cert/mykeystore.jks"), "12345678".toCharArray());

			///////////////////////////////////
			///// CREATE THE KEY MANAGER /////
			//////////////////////////////////
			KeyManagerFactory serverKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
			serverKeyManagerFactory.init(keyStore, "12345678".toCharArray());
			KeyManager[] km = serverKeyManagerFactory.getKeyManagers();


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



	public void start() throws Exception {
		keepGoing = true;

		//////////////////////////////////
		///// CREATE THE SSLCONTEXT /////
		///// AND WAIT CONNECTION  //////
		////////////////////////////////
		SSLContext sslContext = createSSLContext();
		try {
			// the socket used by the server
			SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
			SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory .createServerSocket(port);

			// infinite loop to wait for connections
			while (keepGoing) {
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");

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
		// connect to myself as Client to exit statement
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

		// we loop in reverse order in case we would have to remove a Client
		// because it has disconnected
		for (int i = al.size(); --i >= 0; ) {
			ClientThread ct = al.get(i);
			// try to write to the Client if it fails remove it from the list
			if (!ct.writeMsg(messageLf)) {
				al.remove(i);
				display("Disconnected Client " + ct.username + " removed from list.");
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

	////////////////////////////
	/// Grab the Server cert ///
	////////////////////////////
	public X509Certificate getServerCertificate() throws Exception {
		//Read from the keystore
		FileInputStream input = new FileInputStream(keystoreFile);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(input, keyStorePwd.toCharArray());
		X509Certificate serverCert = (X509Certificate) keyStore.getCertificate(serverAlias);

		return serverCert;
	}

	public PrivateKey getPrivateKey() throws Exception {
		FileInputStream input = new FileInputStream(keystoreFile);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(input, keyStorePwd.toCharArray());
		KeyStore.PrivateKeyEntry keyEnt = (KeyStore.PrivateKeyEntry) keyStore.getEntry(serverAlias,
				new KeyStore.PasswordProtection(keyStorePwd.toCharArray()));
		PrivateKey privateKey = keyEnt.getPrivateKey();

		return privateKey;
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
		// the Username of the Client
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
				X509Certificate serverCert = getServerCertificate();
				System.out.println(clientMsg);
				if (clientMsg.equals("Hello Server")) {
					sOutput.writeObject("Hello Client\nThis is my Certificate: ");
					sOutput.writeObject(serverCert);

					if (((String) sInput.readObject()).contains("Trusted Server")) {
						PrivateKey serverPrivateKey = getPrivateKey();
						Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
						cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
						byte[] decryptedUserName = cipher.doFinal((byte[]) sInput.readObject());
						byte[] decryptedPwd = cipher.doFinal((byte[]) sInput.readObject());
						System.out.println("Decrypted Username:\n" + new String (decryptedUserName));
						System.out.println("Decrypted Password:\n" + new String (decryptedPwd));

					}
				} else {
					System.out.println("Failed: Client never send Hello text");
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
				// the messaage part of the ChatMessage
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
         * Write a String to the Client output stream
         */
		private boolean writeMsg(String msg) {
			// if Client is still connected send the message to it
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
     * > java Server
     * > java Server portNumber
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
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
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
