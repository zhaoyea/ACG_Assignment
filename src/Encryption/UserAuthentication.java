package Encryption;

import java.io.FileReader;
import java.io.LineNumberReader;

/**
 * Created by tanzh on 25/01/2017.
 */
public class UserAuthentication {
    private static final String USERS_FILE_NAME = "src/Users/users.txt";

    public static int VerfiyUser(String PlainUsername, String PlainPwd) throws Exception {
        //http://stackoverflow.com/questions/15332406/extracting-specific-text-from-a-file-in-java
        LineNumberReader reader = new LineNumberReader(new FileReader(USERS_FILE_NAME));
        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith(PlainUsername)) {
                for (int i = reader.getLineNumber(); i <= reader.getLineNumber(); i++) {
                    String dbUsername = line.split(":")[0];
                    String dbSalt = line.split(":")[2];
                    String dbHashedPwd = line.split(":")[3];
                    byte[] salt = Hash.hexStringToByteArray(dbSalt);

                    String HashedPwd = Hash.asHex(Hash.hashPassword(PlainPwd.toCharArray(), salt, 1000, 512));
                    if (dbUsername.equals(PlainUsername) && HashedPwd.equals(dbHashedPwd)) {
                        System.out.println("Hello " + dbUsername);
                        return 1;
                    } else {
                        System.out.printf("Error: Sorry! No Such user. Please register to log in!\n");
                        System.exit(0);
                    }
                }
                break;
            }
        }
        return 0;
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

