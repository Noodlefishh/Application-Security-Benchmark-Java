package com.vulnerable.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

/**
 * VULNÉRABILITÉ: A05:2021 - Security Misconfiguration
 * VULNÉRABILITÉ: XML External Entities (XXE)
 */
@Controller
@RequestMapping("/xml")
public class XmlController {

    /**
     * VULNÉRABILITÉ: XXE - XML External Entity Injection
     * Le parser XML n'est pas configuré pour désactiver les entités externes
     */
    @PostMapping("/parse")
    @ResponseBody
    public String parseXml(@RequestBody String xmlContent) {
        try {
            // VULNÉRABILITÉ: Parser XML non sécurisé
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // Ces lignes sont commentées intentionnellement pour créer la vulnérabilité XXE
            // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            // factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            // factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            // factory.setXIncludeAware(false);
            // factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));

            return "XML parsé avec succès! Root element: " + doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "Erreur lors du parsing XML: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Information Disclosure
     * Exemple de payload XXE:
     * <?xml version="1.0"?>
     * <!DOCTYPE foo [
     *   <!ENTITY xxe SYSTEM "file:///etc/passwd">
     * ]>
     * <root>&xxe;</root>
     */
    @GetMapping("/example")
    @ResponseBody
    public String getExample() {
        return "Envoyez du XML à /xml/parse pour le parser\n\n" +
               "Exemple de payload XXE:\n" +
               "<?xml version=\"1.0\"?>\n" +
               "<!DOCTYPE foo [\n" +
               "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n" +
               "]>\n" +
               "<root>&xxe;</root>";
    }
}
