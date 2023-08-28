package eu.napcore.security.soap;

import java.io.File;
import java.io.FileNotFoundException;

import javax.xml.soap.SOAPException;

public class Main {

	public static void main(String[] args) throws SOAPException, FileNotFoundException {
		SoapMessageReader r = new SoapMessageReader();
		r.createSoap(new File("test/testData/SampleDLMforPredefinedZoneSegmentSection.xml"));
	}

}
