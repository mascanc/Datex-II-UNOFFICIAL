package eu.napcore.security.soap;

import java.io.File;
import java.io.FileNotFoundException;

import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;


public class MainSoap {

	public static void main(String[] args) throws SOAPException, FileNotFoundException {
		SoapMessageReader r = new SoapMessageReader();
		SOAPMessage message = r.createSoap(new File("test/testData/xml/SampleDLMforPredefinedZoneSegmentSection.xml"));
		r.signEnvelope(message);
		
	}

}
