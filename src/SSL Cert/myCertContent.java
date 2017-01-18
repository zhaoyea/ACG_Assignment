/***************************************************************
 *
 * A Simple Program to Print the Public Certificate Information
 *
 * Written by Samson Yeow
 *
 * Singapore Polytechnic
 *
 * (c) Jul 2011. Singapore Polytechnic
 *
 ***************************************************************/

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class myCertContent {

  public static void main (String[] args) throws Exception {

	if (args.length != 1) {
		System.out.println("Usage: java myCertContent certificate_name");
		return;
	}

	// Get the instance from the CertificateFactory class
        // Insert your statement here
	CertificateFactory cert = CertificateFactory.getInstance("X.509");

	// Open the file input stream
	FileInputStream info = new FileInputStream (args[0]);

	// Generate a certificate from that file
	Certificate printCert = cert.generateCertificate(info);
	info.close();

    //Create X509Certificate object
    X509Certificate t = (X509Certificate) printCert;



	// Display the information in the certificate
      System.out.println("Verson: "+ t.getVersion());
      System.out.println("Serial No: "+ t.getSerialNumber().toString(16));
      byte[] sig = t.getSignature();
      System.out.println("\nSignature: \n"+new BigInteger(sig).toString(16));

      //Exercise 3
      PublicKey pk = t.getPublicKey();
      System.out.println("\nPublic Key: \n");
      byte [] pkenc = pk.getEncoded();
      for (int i=0; i< pkenc.length; i++) {
          System.out.print(pkenc[i] + " , ");
      }
    }  // End for

  } //End Main