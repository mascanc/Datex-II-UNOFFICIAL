package eu.napcore.security;

public class Scrapbook {
	/** The RSA key of the client */
	private String clientKey = "test/testData/junk/salvatorekey.der";

	/** The RSA certificate of the server */
	private String clientCert = "test/testData/clientCert.der";

	/** The certificate of the CA */
	private String cacert = "test/testData/cacert.der";
	
	/** The url of the CRL. NOTE: the CRL is a file, and not obtained from the distribution point */
	private String crlUrl = "test/testData/crl.der";

}
