package Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Created by tanzh on 25/01/2017.
 *
 * @@ -24,12 +27,12 @@
 **/
public class CryptoUtils {

    //////////////////////////////////
    ///// Ecnryption of Messages /////
    //////////////////////////////////
    public static String encrypt(String unencryptedString, SecretKey key, Cipher cipher) {
        byte[] cipherText = null;
        String encryptedString = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes("utf-8");

            //encyrpt the plaintext
            cipherText = cipher.doFinal(plainText);

            //Encode the cipherText into Base64
            encryptedString = new String(Base64.getEncoder().encode(cipherText));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }

    private static final String UNICODE_FORMAT = "UTF-8";


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
}
