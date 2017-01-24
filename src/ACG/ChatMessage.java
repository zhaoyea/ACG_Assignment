package ACG;

import java.io.Serializable;

/*
 * This class defines the different type of messages that will be exchanged between the
 * Clients and the ACG.Server.
 * When talking from a Java ACG.Client to a Java ACG.Server a lot easier to pass Java objects, no
 * need to count bytes or to wait for a line feed at the end of the frame
 */
public class ChatMessage implements Serializable {

	protected static final long serialVersionUID = 1112122200L;

	// The different types of message sent by the ACG.Client
	// WHOISIN to receive the list of the users connected
	// MESSAGE an ordinary message
	// LOGOUT to disconnect from the ACG.Server
	static final int WHOISIN = 0, MESSAGE = 1, LOGOUT = 2;
	private int type;
	private String message;

	// constructor
	ChatMessage(int type, String message) {
		this.type = type;
		this.message = message;
	}

	// getters
	int getType() {
		return type;
	}
	String getMessage() {
		return message;
	}
}
