package eu.napcore.security.soap;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.stream.Stream;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.xerces.jaxp.validation.XMLSchemaFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;


public class SoapMessageReader {

	private WSSecurityEngine secEngine = new WSSecurityEngine();
	private CallbackHandler callbackHandler = new KeystoreCallbackHandler();
	private Crypto crypto = new NapcoreCrypto();
	
	public SoapMessageReader() {
		org.apache.xml.security.Init.init();
        

	}

	/**
	 * Programmatically create a SOAP Envelope from a body XML
	 * 
	 * @param sampleBody the file containing the XML to be added in the body
	 * @throws SOAPException if the creation of the message do not succeed
	 */
	public SOAPMessage createSoap(File sampleBody) throws SOAPException {

		MessageFactory msgFactory = MessageFactory
				.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);


		String soap = SOAPConstants.URI_NS_SOAP_1_2_ENVELOPE;
		try {
			FileInputStream fis = new FileInputStream(sampleBody);

			/*
			 * Create the document builder factory
			 */
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();

			/*
			 * Doc is the document of the SOAP Envelope
			 */
			Document doc = db.newDocument();
			Element soapEnv = doc.createElementNS(soap, "soapenv:Envelope");
			soapEnv.setAttribute("xmlns:soapenv", soap);

			Element soapHeader = doc.createElementNS(soap, "soapenv:Header");
			Element soapBody = doc.createElementNS(soap, "soapenv:Body");
			soapEnv.appendChild(soapHeader);
			soapEnv.appendChild(soapBody);


			/*
			 * This is the payload
			 */
			Document domXml = db.parse(fis);
			Node n = soapBody.getOwnerDocument().adoptNode(domXml.getFirstChild());
			Node n1 = soapBody.getOwnerDocument().importNode(n, true);
			soapBody.appendChild(n1);

			// Now soapenv should be the entire SOAP

			SOAPMessage sm = msgFactory.createMessage();
			Document envDoc = sm.getSOAPBody().getOwnerDocument();

			NodeList nl = soapEnv.getElementsByTagNameNS(SOAPConstants.URI_NS_SOAP_1_2_ENVELOPE, "Body");
			Element body = (Element) nl.item(0);
			if (body == null) {
				throw new SOAPException("Body is null or soap version mismatch");
			}
			NodeList nlBody = body.getChildNodes();
			for (int i = 0; i < nlBody.getLength(); i++) {
				Node t1 = envDoc.importNode(nlBody.item(i), true);
				sm.getSOAPBody().appendChild(t1);
			}
			sm.saveChanges();
			return sm;

		} catch ( ParserConfigurationException | SAXException | IOException e) {
			throw new SOAPException("Unable to build the SOAP ", e);
		}

	}

	/**
	 * Pretty print an XML document
	 * @param document
	 * @return
	 */
	public static String printMessage(Document document) {
		try {
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			transformerFactory.setAttribute("indent-number", 2);
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");

			Writer out = new StringWriter();
			transformer.transform(new DOMSource(document), new StreamResult(out));
			return out.toString();
		} catch (Exception e) {
			throw new RuntimeException("Error occurs when pretty-printing xml:\n", e);
		}
	}

	/**
	 * Pretty print a SOAP
	 * 
	 * @param message
	 * @return
	 */
	public static String printMessage(SOAPMessage message) {

		try {


			Document document = message.getSOAPBody().getOwnerDocument();

			return printMessage(document);
		} catch (Exception e) {
			throw new RuntimeException("Error occurs when pretty-printing xml:\n", e);
		}


	}

	public void signEnvelope(SOAPMessage message)  {

		Document envelope = message.getSOAPPart().getOwnerDocument();
		
		WSSecHeader secHeader = new WSSecHeader(envelope);
		try {
			secHeader.insertSecurityHeader();
			WSSecSignature builder = new WSSecSignature(secHeader);
			builder.setUserInfo("fake", "security");
			builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
			builder.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			builder.setDigestAlgo("http://www.w3.org/2001/04/xmlenc#sha256");
			WSSecTimestamp secTS = new WSSecTimestamp(secHeader);
			secTS.build();

			Document signedDoc = builder.build(crypto);
			
			

			System.out.println(printMessage(signedDoc));
			
			LinkedList<StreamSource> schemas = new LinkedList<>();
			
			try (Stream<Path> paths = Files.walk(Paths.get("test/testData/xml"))) {
			    paths
			        .filter(Files::isRegularFile)
			        .forEach(x -> {
			        	StreamSource t = new StreamSource(x.toFile());
			        	schemas.add(t);
			        });
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
			
			
			XMLSchemaFactory xmlSchemaFactory = new XMLSchemaFactory();
			Schema schema = xmlSchemaFactory.newSchema((Source[]) schemas.toArray());     
			Validator validator = schema.newValidator();
			validator.validate(new DOMSource(signedDoc));

		} catch (WSSecurityException | SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



	}
}
