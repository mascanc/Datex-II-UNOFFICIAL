package eu.napcore.security;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;


/**
 * Entry point for all the NAPCORE tests involving network Communications. 
 * 
 * NOTE: this class is just an example, and it must not be used in production 
 * environments. 
 * 
 * There is no logging framework, the output is just on the STDOUT ad STDERR. 
 * When throwing an exception, the program exits with a negative code. 
 * 
 * August 9, 2023
 * 
 * @author mmasi@autostrade.it
 * 
 */
public class MainHardCodedPinning {
	
	
	/** This is the URL of the remote service to contact. It is a fake url for a TOMCAT */
	private static String remoteURL = "https://192.168.1.36:8443";

	/** The hardcoded key. */
	private static String hardcodedKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7UR2ScyPlOf7H6GNvxFegtJVbdPH6id3db7ZcUMTMoSBBqSj8zQpuKVbnjntrv2TYc6pZD+T5Xsg4Thg0RFilst47S34i2alEtzDOlBbuI/wnkZ2wox6pm1dncWC5E1HG2/5Vcxi9XeT7abjFbQLNkvH9iKBTv2jJEjbbde6YlWjQCaziSKKmIUrzb84IU/q584KaPsztmH1jFLLObOCCnWjnBr4Bfaz7LNIrIbz8ufpYubiF/cxKQ/WS1/7CfVqWaYa2awX00D+ziSWIVsYjLyuc5Z76aLLHunnfRyUZtoy/qLhlRPHOFFEjVg+41cMCeUVsv3r4fFUEB29knYuvwIDAQAB";
	/** Should I pin the TLS certificate? */
	private static boolean tlsPinning = true;



	public static void main(String[] args) {

		/* 
		 * TLSSocket is the entry that contains the information about establishing
		 * a socket. Certificates are set here. 
		 */
		TLSSocket socket = new TLSSocket();
		SSLSocketFactory ssf = null;

		try {
			ssf = socket.createSocketFactory();

		} catch (UnrecoverableKeyException e) {
			System.err.println("An error occurred when trying to recover the key: " + e.getMessage());
			System.exit(-1);
		} catch (KeyManagementException e) {
			System.err.println("An error occurred when trying to obtaining the key: " + e.getMessage());
			System.exit(-2);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("An error occurred when trying to defining the default algorithm: " + e.getMessage());
			System.exit(-3);
		} catch (InvalidKeySpecException e) {
			System.err.println("An error occurred when trying to obtaining the key: " + e.getMessage());
			System.exit(-4);
		} catch (CertificateException e) {
			System.err.println("An error occurred with the certificate: " + e.getMessage());
			System.exit(-5);
		} catch (KeyStoreException e) {
			System.err.println("An error occurred when trying to store the key in the keystore: " + e.getMessage());
			System.exit(-6);
		} catch (IOException e) {
			System.err.println("An error occurred when trying to perform I/O: " + e.getMessage());
			System.exit(-7);
		} catch (CRLException e) {
			System.err.println("An error occurred when trying to load CRL: " + e.getMessage());
			System.exit(-12);
		}

		/*
		 * Establish the url connection with the custom socket factory
		 */
		HttpsURLConnection.setDefaultSSLSocketFactory(ssf);

		/*
		 * Custom code to verify the certificate, for pinning, CRL, OCSP, and CT.
		 */
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {


			@Override
			public boolean verify(String arg0, SSLSession arg1) {
				System.out.println("Verifying certificate for endpoint with IP" + arg0);
				System.out.println("Ciphersuite is "+arg1.getCipherSuite());
				try {
					Certificate[] cert = arg1.getPeerCertificates();
					System.out.println("Obtained a chain of " + cert.length + " certificates");

					// The first certificate is the leaf up to the chain.
					// NOTE: we verify the CRL just for the LEAF!!! This is not 
					// correct WE HAVE TO VERIFY FOR EVERY SINGLE CERTIFICATE!!!! @FIXME 

					System.out.println("Checking for CRL");
					X509Certificate leafCert = (X509Certificate)cert[0];
					leafCert.checkValidity();
					X509Certificate cacert = (X509Certificate)cert[1];
					cacert.checkValidity();
					X509CRLEntry isRevoked = socket.getCrl().getRevokedCertificate(leafCert);

					if (isRevoked != null) {
						throw new SSLPeerUnverifiedException("The certificate from the server is revoked");
					} 

					
					/*
					 * Now we try to pin the certificate. The certificates to be pinned are all 
					 * the one which are verified before in the PKIX
					 */
					
					if (tlsPinning) {
						
						if (!Base64.getEncoder().encodeToString(leafCert.getPublicKey().getEncoded()).equals(hardcodedKey)) {
							System.out.println(Base64.getEncoder().encodeToString(leafCert.getPublicKey().getEncoded()));
							System.out.println(hardcodedKey);
							throw new SSLPeerUnverifiedException("The certificate is not pinned!");
						} else {
							System.out.println("Pin is ok");
						}
						
					}
				} catch (SSLPeerUnverifiedException e) {
					System.err.println("Obtained an exception when verifiying the certificate " + e.getMessage());
					System.exit(-20);
				} catch (CertificateExpiredException e) {
					System.err.println("The certificate is expired " + e.getMessage());
					System.exit(-21);
				} catch (CertificateNotYetValidException e) {
					System.err.println("The certificate is not yet valid " + e.getMessage());
					System.exit(-22);
			
				} catch (CertificateException e1) {
					System.err.println("The truststore is corrupted, or I cannot access it (Cert Exception) " + e1.getMessage());
					System.exit(-23);
				
				} 
				System.out.println("END Checking CRL revocation ");
				return true;
			}
		});
		
		
		URL url=null;
		try {
			url = new URL(remoteURL);
		} catch (MalformedURLException e) {
			System.err.println("The URL is malformed: " + e.getMessage());
			System.exit(-8);
		}


		HttpsURLConnection con=null;
		
		
		
		try {
			con = (HttpsURLConnection) url.openConnection();
		} catch (IOException e) {
			System.err.println("Unable to connect: " + e.getMessage());
			System.exit(-9);
		}

		con.setRequestProperty("User-Agent", "Original Application");

		try {
			System.out.println("Response code " + con.getResponseCode());
		} catch (IOException e) {
			System.err.println("An error occurred when trying to perform I/O during the connection: " + e.getMessage());
			System.exit(-10);
		}

	}

	

}
