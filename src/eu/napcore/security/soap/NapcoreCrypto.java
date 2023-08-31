package eu.napcore.security.soap;

import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.regex.Pattern;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;

import eu.napcore.security.TLSSocket;

public class NapcoreCrypto implements Crypto {

	private TLSSocket certHolder;

	public NapcoreCrypto() {
		try {
			certHolder = new TLSSocket();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | CertificateException | KeyStoreException
				| CRLException e) {
			throw new IllegalStateException("Unable to setup the certificates",e);
		}
	}
	@Override
	public byte[] getBytesFromCertificates(X509Certificate[] arg0) throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public CertificateFactory getCertificateFactory() throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate[] getCertificatesFromBytes(byte[] arg0) throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCryptoProvider() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getDefaultX509Identifier() throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PrivateKey getPrivateKey(X509Certificate arg0, CallbackHandler arg1) throws WSSecurityException {
		// TODO Auto-generated method stub
		return certHolder.getPrivateKey();
	}

	@Override
	public PrivateKey getPrivateKey(PublicKey arg0, CallbackHandler arg1) throws WSSecurityException {
		// TODO Auto-generated method stub
		return certHolder.getPrivateKey();
	}

	@Override
	public PrivateKey getPrivateKey(String arg0, String arg1) throws WSSecurityException {
		// TODO Auto-generated method stub
		return certHolder.getPrivateKey();
	}

	@Override
	public byte[] getSKIBytesFromCert(X509Certificate arg0) throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getTrustProvider() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate[] getX509Certificates(CryptoType arg0) throws WSSecurityException {
		
		return new X509Certificate[] {certHolder.getCertificate()};
	}

	@Override
	public String getX509Identifier(X509Certificate arg0) throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public X509Certificate loadCertificate(InputStream arg0) throws WSSecurityException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setCertificateFactory(CertificateFactory arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setCryptoProvider(String arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setDefaultX509Identifier(String arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setTrustProvider(String arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void verifyTrust(PublicKey arg0) throws WSSecurityException {
		// TODO Auto-generated method stub

	}

	@Override
	public void verifyTrust(X509Certificate[] arg0, boolean arg1, Collection<Pattern> arg2, Collection<Pattern> arg3)
			throws WSSecurityException {
		// TODO Auto-generated method stub

	}

}
