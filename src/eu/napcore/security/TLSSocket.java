package eu.napcore.security;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * TLSSocket - Class that deals with the socket establishment. 
 * 
 * The code is just for reasonings of the NAPCORE building blocks, and it should
 * not be used in production environment. It lacks functionalities, and 
 * does not implement properly the security considerations of the various protocols. 
 * 
 * August 9, 2023
 * 
 * @author mmasi@autostrade.it
 */
public class TLSSocket {

	/**
	 * Holders of the various managers
	 */
	private static X509TrustManager defaultTrustManager;
	private static X509KeyManager defaultKeyManager;
	private X509CRL crl;
	
	/** Set the random number generator. This is set unique to avoid guessing */
	private static SecureRandom rand = new SecureRandom();


	/** The RSA key of the client */
	private String clientKey = "test/testData/clientKey.der";

	/** The RSA certificate of the client */
	private String clientCert = "test/testData/clientCert.der";

	/** The RSA certificate of the serfver */
	private String serverCert = "test/testData/servercert.der";
	
	/** The certificate of the CA */
	private String cacert = "test/testData/cacert.der";
	
	/** The url of the CRL. NOTE: the CRL is a file, and not obtained from the distribution point */
	private String crlUrl = "test/testData/crl.der";
	
	/** The keystore, containing private and public keys. */
	private KeyStore ks;
	
	/** The truststore, containing the CAcerts and the certificate to pin. */
	private KeyStore ts;
	
	/** The truststore which is used to test the certificate pinning. This conrtains the server cert. */
	private KeyStore testts;
	
	/** Contains the certificate to be used when signing. */
	private X509Certificate cert;
	
	/** Contains the private key to be used when signing. */
	private RSAPrivateKey rsaKey;

	/**
	 * Obtain the truststore under test/testData/truststore.jks
	 * @return
	 * @throws KeyStoreException 
	 * @throws CertificateException 
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 */
	public KeyStore getTestTruststore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
		FileInputStream fcert = new FileInputStream(serverCert);
		FileInputStream fca = new FileInputStream(cacert);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		X509Certificate cert = (X509Certificate) cf.generateCertificate(fcert);
		X509Certificate ca = (X509Certificate) cf.generateCertificate(fca);

		X509Certificate[] chain = new X509Certificate[2];
		chain[0] = cert;
		chain[1] = ca;

		testts = KeyStore.getInstance("JKS"); // load truststore

		testts.load(null, null);
		testts.setCertificateEntry("1", cert);
		testts.setCertificateEntry("2", ca);
		return testts;
	}
	/**
	 * Obtains the truststore that has been used to establish the socket
	 * @return the truststore
	 */
	public KeyStore getTruststore() {
		return ts;
	}
	
	public TLSSocket() throws NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException, CRLException {	
		
		/*
		 * Create the container trust and key store
		 */
		try (FileInputStream fkey = new FileInputStream(clientKey)) {
			KeyFactory factory = KeyFactory.getInstance("RSA");

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int bytesRead = -1;
			while ((bytesRead = fkey.read()) != -1) {
				baos.write(bytesRead);
			}

			KeySpec spec = new PKCS8EncodedKeySpec(baos.toByteArray());
			rsaKey = (RSAPrivateKey) factory.generatePrivate(spec);

			FileInputStream fcert = new FileInputStream(clientCert);
			FileInputStream fca = new FileInputStream(cacert);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			cert = (X509Certificate) cf.generateCertificate(fcert);
			X509Certificate ca = (X509Certificate) cf.generateCertificate(fca);

			X509Certificate[] chain = new X509Certificate[2];
			chain[0] = cert;
			chain[1] = ca;

			ks = KeyStore.getInstance("JKS"); // load keystore
			ts = KeyStore.getInstance("JKS"); // load truststore

			ks.load(null, null);
			ts.load(null, null);
			ks.setKeyEntry("1", rsaKey, "changeit".toCharArray(), chain);
			ts.setCertificateEntry("1", cert);
			ts.setCertificateEntry("2", ca);
			
			setCrl((X509CRL) cf.generateCRL(new FileInputStream(crlUrl)));

		} catch (IOException e) {
			throw new IllegalStateException("Unable to read the key file");
		}

	}
	/**
	 * Create a socket factory, with the specific certificate and cert chain
	 * 
	 * @return the socket factory
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws KeyManagementException 

	 */
	public SSLSocketFactory createSocketFactory() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException  {

		

			TrustManagerFactory trustMgrFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustMgrFactory.init(ts);
			TrustManager trustManagers[] = trustMgrFactory.getTrustManagers();
			for (int i = 0; i < trustManagers.length; i++) {
				if (trustManagers[i] instanceof X509TrustManager) {
					setDefaultTrustManager((X509TrustManager) trustManagers[i]);
				}
			}

			KeyManagerFactory keyManagerFactory = KeyManagerFactory
					.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(ks, "changeit".toCharArray());

			KeyManager keymanagers[] = keyManagerFactory.getKeyManagers();
			for (int i = 0; i < keymanagers.length; i++) {
				if (keymanagers[i] instanceof X509KeyManager) {
					setDefaultKeyManager((X509KeyManager) keymanagers[i]);
				}
			}

			SSLContext sslCtx = SSLContext.getInstance("TLS");
			sslCtx.init(keyManagerFactory.getKeyManagers(), trustMgrFactory.getTrustManagers(), null);

			SSLSocketFactory ssf = sslCtx.getSocketFactory();

			return ssf;
		
	}

	public static X509TrustManager getDefaultTrustManager() {
		return defaultTrustManager;
	}

	public static void setDefaultTrustManager(X509TrustManager defaultTrustManager) {
		TLSSocket.defaultTrustManager = defaultTrustManager;
	}

	public static X509KeyManager getDefaultKeyManager() {
		return defaultKeyManager;
	}

	public static void setDefaultKeyManager(X509KeyManager defaultKeyManager) {
		TLSSocket.defaultKeyManager = defaultKeyManager;
	}

	public X509CRL getCrl() {
		return crl;
	}

	public void setCrl(X509CRL crl) {
		this.crl = crl;
	}

	/**
	 * Obtains the OCSP Url from the Attribute Key Authority (OID: 1.3.6.1.5.5.7.1.1)
	 * 
	 * @param certificate
	 * @return
	 * @throws IOException
	 */
	public static String getOcspUrl1(X509Certificate c) throws IOException {
		byte[] ext = c.getExtensionValue("1.3.6.1.5.5.7.1.1");
		ASN1InputStream ais1 = new ASN1InputStream(new ByteArrayInputStream(ext));
		DEROctetString oct = (DEROctetString) (ais1.readObject());
		try (ASN1InputStream ais2 = new ASN1InputStream(oct.getOctets())) {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ais2.readObject());
			AccessDescription[] ad = aia.getAccessDescriptions();
			AccessDescription ad1 = ad[0];
			GeneralName al = ad1.getAccessLocation();

			return al.getName().toString();

		}
	}

	/**
	 * Verify the certificate using OCSP via HTTP
	 * 
	 * @param leafCert the certificate to check
	 * @param url the URL of the OCSP responder
	 * @throws Exception
	 */
	public static void verify(X509Certificate leafCert, String url) throws Exception {

		/*
		 * Build the data structures for the OCSP request, according with RFC 6960. 
		 * OCSP is a HTTP GET with a content in ASN1
		 */
		X509CertificateHolder holder = new JcaX509CertificateHolder(leafCert);
		JcaDigestCalculatorProviderBuilder builder = new JcaDigestCalculatorProviderBuilder();
		DigestCalculatorProvider dcb = builder.setProvider(new BouncyCastleProvider()).build();
		org.bouncycastle.cert.ocsp.CertificateID certID = new org.bouncycastle.cert.ocsp.CertificateID(
				dcb.get(CertificateID.HASH_SHA1), holder, leafCert.getSerialNumber());

		OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
		reqBuilder.addRequest(certID);


		byte[] sampleNonce = new byte[16];
		rand.nextBytes(sampleNonce);

		ExtensionsGenerator extGen = new ExtensionsGenerator();
		extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(sampleNonce));

		reqBuilder.setRequestExtensions(extGen.generate());
		OCSPReq req = reqBuilder.build();

		URL urlConn = new URL(url);
		HttpURLConnection con = (HttpURLConnection) urlConn.openConnection();
		con.setRequestProperty("Content-Type", "application/ocsp-request");
		con.setRequestProperty("Accept", "application/ocsp-response");
		con.setDoOutput(true);
		OutputStream out = con.getOutputStream();
		DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
		dataOut.write(req.getEncoded());
		dataOut.flush();
		dataOut.close();

		InputStream in = (InputStream) con.getContent();
		OCSPResp ocspResponse = new OCSPResp(in);

		validate(ocspResponse);

	}

	/**
	 * Validate the OCSP Response, and throws exception if the certificate is revoked
	 * or there is an error
	 * @param ocspResponse
	 * @throws OCSPException
	 */
	private static void validate(OCSPResp ocspResponse) throws OCSPException {
		BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();

		SingleResp[] responses = (basicResponse == null) ? null : basicResponse.getResponses();

		if (responses == null) {
			throw new OCSPException("No response returned in the OCSPResp");
		} else {
			int size = responses.length;

			System.out.println("OCSP: got " + size + " responses");
			for (int i = 0; i < responses.length; i++) {
				SingleResp resp = responses[i];

				Date nextUpdate = resp.getNextUpdate();

				if (nextUpdate != null) {
					// It is useless to perform additional requests before this date.
					// Here we should cache the revocation status for the cert with the given serial
					// number
					System.out.println("OCSP: nextUpdate of the record foreseen: " + nextUpdate.toString());

					if (resp.getCertStatus() == CertificateStatus.GOOD) {
						System.out.println("The certificate is GOOD");
					} else {
						System.out.println("The certificate status is either unknown or revoked");
						throw new OCSPException("The certificate is either unknown or revoked");
					}
				}

			}
		}

	}
	
	public PrivateKey getPrivateKey() {
		return this.rsaKey;
	}
	
	public X509Certificate getCertificate() {
		return this.cert;
	}
}