package nbelsev.test.xxe;

import org.xml.sax.InputSource;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import java.io.*;
import java.util.stream.Collectors;

public class CommandLineDemo {
	private static String readResource(String filename) {
		return (new BufferedReader(new InputStreamReader(ClassLoader.getSystemResourceAsStream(filename)))).lines().collect(Collectors.joining(System.lineSeparator()));
	}
	
	private static void loadAndPrintXml(String xml) throws Exception {
		SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
		SAXParser saxParser = saxParserFactory.newSAXParser();
		PersonXMLHandler handler = new PersonXMLHandler();
		saxParser.parse(new InputSource(new StringReader(xml)), handler);
		System.out.println("[+] Person name='" + handler.name + "'");
		System.out.println("[+] Person age=" + handler.age);
	}
	
	/**
	 * Command-line test app to test various XSD schema-based XML validation methods.
	 */
	public static void main(String[] args) throws Exception {
		String xsdFile = "GoodSchema.xsd";
		String xmlFile = "GoodXml.xml";
		
		if(args.length == 3) {
			xsdFile = args[1];
			xmlFile = args[2];
		}
		
		String xsd = readResource(xsdFile);
		String xml = readResource(xmlFile);
		
		System.out.println("Testing insecure validation...");
		try {
			XMLValidator.validate_insecure(xsd, xml);
			System.out.println("[+] Successful validation!");
		} catch(Exception ex) {
			System.out.println("[-] Validation failed.");
			System.out.println("    " + ex.getMessage());
		}
		System.out.println();
		
		System.out.println("Testing validation using OWASP recommendation...");
		try {
			XMLValidator.validate_owaspRec(xsd, xml);
			System.out.println("[+] Successful validation!");
		} catch(Exception ex) {
			System.out.println("[-] Validation failed.");
			System.out.println("    " + ex.getMessage());
		}
		System.out.println();
		
		System.out.println("Testing validation using alternative fix...");
		try {
			XMLValidator.validate_alternateFix(xsd, xml);
			System.out.println("[+] Successful validation!");
		} catch(Exception ex) {
			System.out.println("[-] Validation failed.");
			System.out.println("    " + ex.getMessage());
		}
		System.out.println();
		
		System.out.println("Loading and printing XML...");
		loadAndPrintXml(xml);
	}
}
