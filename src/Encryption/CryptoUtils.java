package Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

//import org.apache.commons.codec.binary.Base64;
//import org.apache.commons.codec.binary.Base64;


/**
 * Created by tanzh on 25/01/2017.
 *
 * @@ -24,12 +27,12 @@
 **/
public class CryptoUtils {

    private static final String UNICODE_FORMAT = "UTF-8";
    static SecretKey key;
    static Cipher cipher;
    static AlgorithmParameterSpec paramSpec;



    public static String encrypt(String unencryptedString, SecretKey key, Cipher cipher) {
        byte[] cipherText = null;
        String encryptedString = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes("utf-8");
            cipherText = cipher.doFinal(plainText);
            encryptedString = new String(Base64.getEncoder().encode(cipherText));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }


    public static String decrypt(String encryptedString, SecretKey key, Cipher cipher) {
        String decryptedText = null;
        try {
            byte[] encryptedText = Base64.getMimeDecoder().decode(encryptedString);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainText = cipher.doFinal(encryptedText);
            decryptedText = new String(plainText, "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedText;
    }



    public static String asHex(byte buf[]) {

        //Obtain a StringBuffer object
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

}
