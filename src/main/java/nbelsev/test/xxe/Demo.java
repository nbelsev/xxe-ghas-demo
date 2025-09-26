package nbelsev.test.xxe;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class Demo {
	/**
	 * Generates 2 GHAS code scanning alerts.
	 * -> "Resolving XML external entity in user-controlled data" on "SchemaFactory.newSchema()"
	 * -> "Resolving XML external entity in user-controlled data" on "Validator.validate()"
	 */
	@GetMapping("/vuln")
	public void validateXml_vulnerable(@RequestParam(name = "xsd") String xsd, @RequestParam(name = "xml") String xml) throws Exception {
		//XMLValidator.validate_insecure(xsd, xml);
	}
	
	/**
	 * Generates no GHAS code scanning alerts.
	 */
	@GetMapping("/owasp-rec")
	public void validateXml_owaspRec(@RequestParam(name = "xsd") String xsd, @RequestParam(name = "xml") String xml) throws Exception {
		//XMLValidator.validate_owaspRec(xsd, xml);
	}
	
	/**
	 * Generates 1 GHAS code scanning alert.
	 * -> "Resolving XML external entity in user-controlled data" on "Validator.validate()"
	 */
	@GetMapping("/alternate-fix")
	public void validateXml_alternateFix(@RequestParam(name = "xsd") String xsd, @RequestParam(name = "xml") String xml) throws Exception {
		XMLValidator.validate_alternateFix(xsd, xml);
	}
}
