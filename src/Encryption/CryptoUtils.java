package Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Created by tanzh on 25/01/2017.
 */
public class CryptoUtils {
    //http://stackoverflow.com/questions/20227/how-do-i-use-3des-encryption-decryption-in-java
    private static final String UNICODE_FORMAT = "UTF8";
    public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";

    static Cipher cipher;
    static SecretKey key;
    static AlgorithmParameterSpec paramSpec;

    public CryptoUtils() throws Exception {
        String myEncryptionKey = "ThisIsSpartaThisIsSparta";
        byte[] arrayBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
        KeySpec ks = new DESedeKeySpec(arrayBytes);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(DESEDE_ENCRYPTION_SCHEME);
        cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        key = skf.generateSecret(ks);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[8];
        random.nextBytes(iv);
        paramSpec = new IvParameterSpec(iv);
    }


    public static String encrypt(String unencryptedString) {
        String encryptedString = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
            byte[] encryptedText = cipher.doFinal(plainText);
            encryptedString = new String(Base64.encodeBase64(encryptedText));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }


    public static String decrypt(String encryptedString) {
        String decryptedText = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] encryptedText = Base64.decodeBase64(encryptedString.getBytes());
            byte[] plainText = cipher.doFinal(encryptedText);
            decryptedText = new String(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedText;
    }

    //sample program
    public static void main(String args[]) throws Exception {
        CryptoUtils cryptoUtils = new CryptoUtils();

        String msg = "Name";
        String encryptMsg = cryptoUtils.encrypt(msg);
        String decryptMsg = cryptoUtils.decrypt(encryptMsg);

        System.out.println("String To Encrypt: " + msg);
        System.out.println("Encrypted String: " + encryptMsg);
        System.out.println("Decrypted String: " + decryptMsg);

    }
}
