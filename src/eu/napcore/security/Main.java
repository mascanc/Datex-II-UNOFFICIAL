package eu.napcore.security;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

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
public class Main {


	/** This is the URL of the remote service to contact. It is a fake url for a TOMCAT */
	private static String remoteURL = "https://192.168.1.36:8444";

	/** Should I check for OCSP? */
	private static boolean checkOCSP = false;

	/** Set to true if a proxy should be used (e.g., BURP suite) */
	private static boolean useProxy = false;

	/** Set the address of the proxy */
	private static String proxyAddress = "192.168.1.2";

	/** Set the port of the proxy */
	private static int proxyPort;

	/** Should I pin the TLS certificate? */
	private static boolean tlsPinning = true;

	/** Variable that holds if a certificate pinned is found */
	private static boolean found = false;

	public static void main(String[] args) {

		/* 
		 * TLSSocket is the entry that contains the information about establishing
		 * a socket. Certificates are set here. 
		 */

		SSLSocketFactory ssf = null;
		try {
			TLSSocket socket = new TLSSocket();
			ssf = socket.createSocketFactory();



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

						if (checkOCSP) {
							// Now checking OCSP
							try {

								String ocspUrl1 = TLSSocket.getOcspUrl1(leafCert);
								System.out.println("Obtained OCSP URL: " + ocspUrl1);
								TLSSocket.verify(leafCert, ocspUrl1);

							} catch (Exception e) {
								e.printStackTrace();
								System.err.println("Unable to obtain the OCSP URL");
								System.exit(-40);
							}
						} else {
							System.out.println("Not checking for OCSP");
						}

						/*
						 * Now we try to pin the certificate. The certificates to be pinned are all 
						 * the one which are verified before in the PKIX
						 */

						if (tlsPinning) {
							KeyStore truststore = socket.getTestTruststore();

							Collections.list(truststore.aliases()).forEach(x -> {
								try {
									X509Certificate tPCert = (X509Certificate) truststore.getCertificate(x);
									System.out.println("Obtained certificate from TLS " + System.lineSeparator() + 
											leafCert.getSubjectX500Principal() + System.lineSeparator() + 
											" and the one that I have in my truststore is " + System.lineSeparator() + 
											tPCert.getSubjectX500Principal());
									if (Arrays.equals(leafCert.getPublicKey().getEncoded(), tPCert.getPublicKey().getEncoded())) {
										System.out.println("Found a certificate to be pinned with key " + 
												Base64.getEncoder().encodeToString(leafCert.getPublicKey().getEncoded()));
										setFoundpinnedCert(true);
										return;
									} else {
										System.out.println("[DEBUG] expected the key :" + System.lineSeparator() 
										+ Base64.getEncoder().encodeToString(tPCert.getPublicKey().getEncoded()) + 
										System.lineSeparator() + ": while "
										+ "I got :" + System.lineSeparator() +
										Base64.getEncoder().encodeToString(leafCert.getPublicKey().getEncoded()));
									}

								} catch (KeyStoreException e) {
									System.err.println("Unable to obtain the key for alias " + x + ": " + e.getMessage());
									System.exit(-24);							}
							});
							if (!getFoundpinnedCert()) {
								throw new SSLPeerUnverifiedException("The certificate " + leafCert + " cannot be found in the truststore");
							} else {
								System.out.println("Certificate for TLS succesfully pinned");
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
					} catch (KeyStoreException e) {
						System.err.println("The truststore is corrupted, or I cannot access it " + e.getMessage());
						System.exit(-23);
					} catch (CertificateException e1) {
						System.err.println("The truststore is corrupted, or I cannot access it (Cert Exception) " + e1.getMessage());
						System.exit(-23);
					} catch (NoSuchAlgorithmException e1) {
						System.err.println("The truststore is corrupted, or I cannot access it (Unknown Algo Exception) " + e1.getMessage());
						System.exit(-23);
					} catch (IOException e1) {
						System.err.println("The truststore is corrupted, or I cannot access it (is servercert in test directory?) " + e1.getMessage());
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

			if (useProxy) {
				Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddress, proxyPort));
				try {
					con = (HttpsURLConnection)url.openConnection(proxy);
				} catch (IOException e) {
					System.err.println("Unable to open connection to the proxy, " + e.getMessage());
					System.err.println(-81);
				}
			}

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
		} catch (CRLException e) {
			System.err.println("An error occurred when trying to load CRL: " + e.getMessage());
			System.exit(-12);
		}

	}


	private static void setFoundpinnedCert(boolean v) {
		found = v;
	}

	private static boolean getFoundpinnedCert() {
		return found;
	}
}
