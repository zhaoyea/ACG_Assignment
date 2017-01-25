package Encryption;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by tanzh on 25/01/2017.
 */
public class UserAuthentication {
    private static final String USERS_FILE_NAME = "src/Users/users.txt";

    public static int FindCurUsername(String PlainUsername, String PlainPwd) throws Exception {
        FileReader fr = new FileReader(USERS_FILE_NAME);
        BufferedReader br = new BufferedReader(fr);
        try {
            String line = br.readLine();
            for (int i = 0; i < line.length(); i++) {
                String dbUsername = line.split(":")[0];
                String dbSalt = line.split(":")[2];
                String dbHashedPwd = line.split(":")[3];
                byte[] salt = Hash.hexStringToByteArray(dbSalt);

                String HashedPwd = Hash.asHex(Hash.hashPassword(PlainPwd.toCharArray(), salt, 1000, 512));
                System.out.println(HashedPwd);
                if (dbUsername.equals(PlainUsername) && HashedPwd.equals(dbHashedPwd)) {
                    System.out.println("Found value username: " + dbUsername);
                    System.out.println("Found value salt: " + dbSalt);
                    System.out.println("Found value hash: " + dbHashedPwd);
                    return 1;
                } else {
                    System.out.printf("Error with the finding of hashed or smth\n");
                    System.exit(0);
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (br != null)
                    br.close();
                if (fr != null)
                    fr.close();
            } catch (IOException ex) {
                ex.printStackTrace();
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

