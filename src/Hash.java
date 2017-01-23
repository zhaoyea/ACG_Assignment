import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by tanzh on 23/01/2017.
 */
public class Hash {
    //https://www.owasp.org/index.php/Hashing_Java
    public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();

            return res;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    //Convert from byte array to hex
    public static String asHex(byte buf[]) {
        // Obtain a StringBuffer object
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        // Return result string in Hexadecimal format
        return strbuf.toString();
    }

    //Random salt
    //https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
    public static byte[] getSalt() {
        try {
            SecureRandom sr = new SecureRandom();
            byte[] salt = new byte[32];
            sr.nextBytes(salt);

            return salt;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //Convert from hex to byte array
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
