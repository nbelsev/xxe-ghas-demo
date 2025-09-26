package nbelsev.test.xxe;

import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLFilterImpl;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import java.io.StringReader;

import static javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI;

public class XMLValidator {
	private static final String DISALLOW_DOCTYPE_DECL = "http://apache.org/xml/features/disallow-doctype-decl";
	private static final String EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities";
	private static final String EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities";
	
	/**
	 * Vulnerable XML validation implementation.
	 */
	public static void validate_insecure(String xsd, String xml) throws Exception {
		SchemaFactory factory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		Schema schema = factory.newSchema(new StreamSource(new StringReader(xsd)));
		Validator validator = schema.newValidator();
		validator.validate(new StreamSource(new StringReader(xml))); //XXE
	}
	
	/**
	 * XML validation secured based on OWASP guidance.
	 * 
	 * See: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#validator
	 */
	public static void validate_owaspRec(String xsd, String xml) throws Exception {
		SchemaFactory factory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		Schema schema = factory.newSchema(new StreamSource(new StringReader(xsd)));
		Validator validator = schema.newValidator();
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		validator.validate(new StreamSource(new StringReader(xml)));
	}
	
	/**
	 * XML validation secured using secure XMLReader and XMLFilterImpl.
	 */
	public static void validate_alternateFix(String xsd, String xml) throws Exception {
		//Create a secure SAX-based XMLReader and use it to create a Schema from the given XSD file (preventing XXE in schema)
		XMLReader securedSchemaReader = createSecureXMLReader(createSecureParserFactory());
		SAXSource securedSchemaSource = new SAXSource(securedSchemaReader, new InputSource(new StringReader(xsd)));
		SchemaFactory securedSchemaFactory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
		securedSchemaFactory.setFeature(DISALLOW_DOCTYPE_DECL, true);
		securedSchemaFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		Schema securedSchema = securedSchemaFactory.newSchema(securedSchemaSource);
		
		//Create a secure SAX-based XMLReader and use it for parsing XML during validation
		XMLReader securedXmlReader = createSecureXMLReader(createSecureParserFactory());
		SAXSource securedXmlSource = new SAXSource(new XMLFilterImpl(securedXmlReader), new InputSource(new StringReader(xml)));
		Validator securedValidator = securedSchema.newValidator();
		securedValidator.validate(securedXmlSource);
	}
	
	/**
	 * Helper method for validate_alternateFix() to create a secure SAXParserFactory.
	 */
	private static SAXParserFactory createSecureParserFactory() throws Exception {
		SAXParserFactory parserFac = SAXParserFactory.newInstance();
		parserFac.setNamespaceAware(true);
		parserFac.setFeature(DISALLOW_DOCTYPE_DECL, true);
		parserFac.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		parserFac.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		parserFac.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		return parserFac;
	}
	
	/**
	 * Helper method for validate_alternateFix() to create a secure XMLReader.
	 */
	private static XMLReader createSecureXMLReader(SAXParserFactory secureParserFac) throws Exception {
		XMLReader reader = secureParserFac.newSAXParser().getXMLReader();
		reader.setFeature(DISALLOW_DOCTYPE_DECL, true);
		reader.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		reader.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		reader.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		return reader;
	}
}
