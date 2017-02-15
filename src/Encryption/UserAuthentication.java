package Encryption;

import java.io.FileReader;
import java.io.LineNumberReader;

/**
 * Created by tanzh on 25/01/2017.
 */
public class UserAuthentication {

    private static final String USERS_FILE_NAME = "src/Users/users.txt";

    public static boolean VerfiyUser(String PlainUsername, String PlainPwd) throws Exception {
        //http://stackoverflow.com/questions/15332406/extracting-specific-text-from-a-file-in-java
        LineNumberReader reader = new LineNumberReader(new FileReader(USERS_FILE_NAME));
        String line;
        String errMsg;

        if (reader.readLine() == null) {
            System.out.println("Error: No such User");
            return false;
        }

        while ((line = reader.readLine()) != null) {
            for (int i = reader.getLineNumber(); i <= reader.getLineNumber(); i++) {
                String dbUsername = line.split(":")[0];
                String dbSalt = line.split(":")[2];
                String dbHashedPwd = line.split(":")[3];
                byte[] salt = HashUtils.hexStringToByteArray(dbSalt);

                String HashedPwd = HashUtils.asHex(HashUtils.hashPassword(PlainPwd.toCharArray(), salt, 1000, 512));
                if (PlainUsername == null || PlainUsername.isEmpty() || PlainPwd == null || PlainPwd.isEmpty()) {
                    errMsg = "Error: Empty Field!\nPlease try again!";
                    System.out.println(errMsg);
                    System.out.println("*************************************");
                    break;
                } else {
                    if (!PlainUsername.equals(dbUsername) && !HashedPwd.equals(dbHashedPwd)) {
                        errMsg = "Error: Username or Password wrong!\nPlease try again!";
                        System.out.println(errMsg);
                        System.out.println("*************************************");
                        break;
                    } else {
                        System.out.println("Login Success!");
                        System.out.println("Hello " + dbUsername);
                        return true;
                    }
                }
            }
            return false;
        }
        return false;
    }

    public static boolean RegisterUserVerfiy(String Username, String Password) throws Exception {
        //http://stackoverflow.com/questions/15332406/extracting-specific-text-from-a-file-in-java
        LineNumberReader reader = new LineNumberReader(new FileReader(USERS_FILE_NAME));
        String line;
        String errMsg;

        if (reader.readLine() == null) {
            if ((!Password.matches("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$"))) {
                errMsg = "Password must include at least:\n - One upper case letter\n - One lower case letter\n - One digit\n - And minium 8 in length";
                System.out.println(errMsg);
                System.out.println("*************************************");
                return false;
            }
        }

        while ((line = reader.readLine()) != null) {
            System.out.println("INSIDE WHILE LOOP");
            for (int i = reader.getLineNumber(); i <= reader.getLineNumber(); i++) {
                System.out.println("INSIDE FOR LOOP");
                String dbUsername = line.split(":")[0];
                System.out.println(dbUsername);

                if (Username == null || Username.isEmpty() || Password == null || Password.isEmpty()) {
                    errMsg = "Error: Username or Password wrong!\nPlease try again!";
                    System.out.println(errMsg);
                    System.out.println("*************************************");
                    break;
                }
                if (dbUsername.equals(Username)) {
                    errMsg = "Error: User already exist!";
                    System.out.println(errMsg);
                    System.out.println("*************************************");
                    break;
                }
                if ((!Password.matches("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$"))) {
                    errMsg = "Password must include at least:\n - One upper case letter\n - One lower case letter\n - One digit\n - And minium 8 in length";
                    System.out.println(errMsg);
                    System.out.println("*************************************");
                    break;
                } else {
                    return true;
                }
            }
        }
        return false;
    }
}

