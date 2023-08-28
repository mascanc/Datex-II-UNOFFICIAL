package eu.napcore.security.soap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class SoapMessageReader {

	public SoapMessageReader() {
		// TODO Auto-generated constructor stub
	}

	public void createSoap(File sampleBody) throws SOAPException, FileNotFoundException {

		MessageFactory msgFactory = MessageFactory
				.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL);
		SOAPMessage request = msgFactory.createMessage();

		SOAPPart msgPart = request.getSOAPPart();
		SOAPEnvelope envelope = msgPart.getEnvelope();
		SOAPBody body = envelope.getBody();

		javax.xml.transform.stream.StreamSource _msg = new javax.xml.transform.stream.StreamSource(new FileInputStream(sampleBody));
		msgPart.setContent(_msg);

		request.saveChanges();
		System.out.println(printMessage(request));
	}

	public static String printMessage(SOAPMessage message) {
		
		 try {
			
		 
//		        InputSource src = new InputSource(new StringReader(xmlString));
//		        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(src);
			 	Document document = message.getSOAPBody().getOwnerDocument();
		        TransformerFactory transformerFactory = TransformerFactory.newInstance();
		        transformerFactory.setAttribute("indent-number", 2);
		        Transformer transformer = transformerFactory.newTransformer();
		        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
		        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, false ? "yes" : "no");
		        transformer.setOutputProperty(OutputKeys.INDENT, "yes");

		        Writer out = new StringWriter();
		        transformer.transform(new DOMSource(document), new StreamResult(out));
		        return out.toString();
		    } catch (Exception e) {
		        throw new RuntimeException("Error occurs when pretty-printing xml:\n", e);
		    }
        
        
	}
}
