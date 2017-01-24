package Encryption;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by tanzh on 24/01/2017.
 */
public class encrypt {

    //////////////////////////////////
    ///// CREATE THE SSL CONTEXT /////
    //////////////////////////////////
    public static SSLContext createSSLContext() {
        try {

            /////////////////////////////////////////
            ///// LOAD THE SERVER'S PRIVATE KEY /////
            /////////////////////////////////////////
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("src/SSL Cert/mykeystore.jks"), "12345678".toCharArray());

            ///////////////////////////////////
            ///// CREATE THE KEY MANAGER /////
            //////////////////////////////////
            KeyManagerFactory serverKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            serverKeyManagerFactory.init(keyStore, "12345678".toCharArray());
            KeyManager[] km = serverKeyManagerFactory.getKeyManagers();


            ////////////////////////////////////
            ///// CREATE THE TRUST MANAGER /////
            ////////////////////////////////////
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
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
        //Declaration of variables to be used
        String keystoreFile = "src/SSL Cert/mykeystore.jks";
        String serverAlias = "server_signed";
        String keyStorePwd = "12345678";

        //Read from the keystore
        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, keyStorePwd.toCharArray());
        X509Certificate serverCert = (X509Certificate) keyStore.getCertificate(serverAlias);

        return serverCert;
    }

    public static PrivateKey getPrivateKey() throws Exception {
        //Declaration of variables to be used
        String keystoreFile = "src/SSL Cert/mykeystore.jks";
        String serverAlias = "server_signed";
        String keyStorePwd = "12345678";

        //https://stackoverflow.com/questions/3027273/how-to-store-and-load-keys-using-java-security-keystore-class
        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, keyStorePwd.toCharArray());
        KeyStore.PrivateKeyEntry keyEnt = (KeyStore.PrivateKeyEntry) keyStore.getEntry(serverAlias,
                new KeyStore.PasswordProtection(keyStorePwd.toCharArray()));
        PrivateKey privateKey = keyEnt.getPrivateKey();

        return privateKey;
    }

    /////////////////////////////////////////
    /// Grab the CA cert for verification ///
    /////////////////////////////////////////
    public static X509Certificate getCACertificate() throws Exception {
        //Declaration of variables to be used
        String keystoreFile = "src/SSL Cert/mykeystore.jks";
        String caAlias = "ca";
        String keyStorePwd = "12345678";

        //Read from the keystore
        FileInputStream input = new FileInputStream(keystoreFile);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(input, keyStorePwd.toCharArray());
        X509Certificate caCert = (X509Certificate) keyStore.getCertificate(caAlias);

        return caCert;

    }


    public static void checkServerCert(X509Certificate cert) throws Exception {
        //http://stackoverflow.com/questions/6629473/validate-x-509-certificate-agains-concrete-ca-java
        if (cert == null) {
            throw new IllegalArgumentException("Null or zero-length certificate chain");
        }
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
