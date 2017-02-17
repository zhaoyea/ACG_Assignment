package Encryption;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by tanzh on 30/01/2017.
 */
public class SSLUtils {
    private static final String KEYSTORE_LOCATION = "src/SSL Cert/mykeystore.jks";
    private static final String SERVER_ALIAS = "server_signed";
    private static final String CA_ALIAS = "ca";
    private static final String KEYSTORE_PWD = "12345678";

    //////////////////////////////////
    ///// CREATE THE SSL CONTEXT /////
    //////////////////////////////////
    public static SSLContext createSSLContext() {
        try {
            /////////////////////////////////////////
            ///// LOAD THE SERVER'S PRIVATE KEY /////
            /////////////////////////////////////////
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE_LOCATION), KEYSTORE_PWD.toCharArray());

            ///////////////////////////////////
            ///// CREATE THE KEY MANAGER /////
            //////////////////////////////////
            KeyManagerFactory serverKeyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            serverKeyManagerFactory.init(keyStore, KEYSTORE_PWD.toCharArray());
            KeyManager[] km = serverKeyManagerFactory.getKeyManagers();


            ////////////////////////////////////
            ///// CREATE THE TRUST MANAGER /////
            ////////////////////////////////////
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
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

    ////////////////////////////
    /// Grab the ACG.Server cert ///
    ////////////////////////////
    public static X509Certificate getServerCertificate() throws Exception {
        //Read from the keystore
        FileInputStream input = new FileInputStream(KEYSTORE_LOCATION);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, KEYSTORE_PWD.toCharArray());
        X509Certificate serverCert = (X509Certificate) keyStore.getCertificate(SERVER_ALIAS);

        return serverCert;
    }

    public static PrivateKey getPrivateKey() throws Exception {
        //https://stackoverflow.com/questions/3027273/how-to-store-and-load-keys-using-java-security-keystore-class
        //Grab the privae key of the server
        FileInputStream input = new FileInputStream(KEYSTORE_LOCATION);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, KEYSTORE_PWD.toCharArray());
        KeyStore.PrivateKeyEntry keyEnt = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SERVER_ALIAS,
                new KeyStore.PasswordProtection(KEYSTORE_PWD.toCharArray()));
        PrivateKey privateKey = keyEnt.getPrivateKey();

        //returnt the key
        return privateKey;
    }

    /////////////////////////////////////////
    /// Grab the CA cert for verification ///
    /////////////////////////////////////////
    public static X509Certificate getCACertificate() throws Exception {
        //Read from the keystore and grab the CACERT
        FileInputStream input = new FileInputStream(KEYSTORE_LOCATION);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, KEYSTORE_PWD.toCharArray());
        X509Certificate caCert = (X509Certificate) keyStore.getCertificate(CA_ALIAS);

        return caCert;

    }

    ////////////////////////////////////////////////
    /// Comparing the CACERT with the ServerCert ///
    ////////////////////////////////////////////////
    public static void checkServerCert(X509Certificate cert) throws Exception {

        //http://stackoverflow.com/questions/6629473/validate-x-509-certificate-agains-concrete-ca-java
        if (cert == null) {
            throw new IllegalArgumentException("Null or zero-length certificate chain");
        }

        //Grab the CaCert
        X509Certificate caCert = getCACertificate();

        //Check if certificate send if your CA's
        if (!cert.equals(caCert)) {
            try {
                cert.verify(caCert.getPublicKey());
            } catch (Exception e) {
                throw new CertificateException("Certificate not trusted", e);
            }
        }
        //If we end here certificate is trusted. Check if it has expired.
        try {
            cert.checkValidity();
        } catch (Exception e) {
            throw new CertificateException("Certificate not trusted. It has expired", e);
        }
    }
}
