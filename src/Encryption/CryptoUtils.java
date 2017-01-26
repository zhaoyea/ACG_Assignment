package Encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.apache.commons.codec.binary.Base64;
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

    public CryptoUtils() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        key = keyGenerator.generateKey();

        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[8];
    }

    public static String encrypt(String unencryptedString) {
        byte[] cipherText = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
            cipherText = cipher.doFinal(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return String.valueOf(cipherText);
    }


    public static String decrypt(String encryptedString) {
        String decryptedText = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] enstring = encryptedString.getBytes(UNICODE_FORMAT);
            byte[] plainText = cipher.doFinal(enstring);
            decryptedText = new String(plainText);
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
