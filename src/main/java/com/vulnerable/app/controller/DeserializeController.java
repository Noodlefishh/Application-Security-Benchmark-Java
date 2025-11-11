package com.vulnerable.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

/**
 * VULNÉRABILITÉ: A08:2021 - Software and Data Integrity Failures
 * Désérialisation non sécurisée
 */
@Controller
@RequestMapping("/deserialize")
public class DeserializeController {

    /**
     * VULNÉRABILITÉ: Insecure Deserialization
     * Accepte et désérialise des objets Java arbitraires
     */
    @PostMapping("/object")
    @ResponseBody
    public String deserializeObject(@RequestParam String data) {
        try {
            // VULNÉRABILITÉ: Désérialisation d'objets non fiables
            byte[] decodedData = Base64.getDecoder().decode(data);

            ByteArrayInputStream bis = new ByteArrayInputStream(decodedData);
            ObjectInputStream ois = new ObjectInputStream(bis);

            // DANGEREUX: Peut exécuter du code arbitraire
            Object obj = ois.readObject();
            ois.close();

            return "Objet désérialisé: " + obj.toString() +
                   "<br>Classe: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Erreur lors de la désérialisation: " + e.getMessage() +
                   "<br>Stack trace: <pre>" + getStackTrace(e) + "</pre>";
        }
    }

    /**
     * VULNÉRABILITÉ: Accepte des objets sérialisés via POST
     */
    @PostMapping("/session")
    @ResponseBody
    public String deserializeSession(@RequestBody byte[] sessionData) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(sessionData);
            ObjectInputStream ois = new ObjectInputStream(bis);

            Object session = ois.readObject();
            ois.close();

            return "Session désérialisée: " + session.toString();
        } catch (Exception e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * Helper pour sérialiser un objet (pour les tests)
     */
    @GetMapping("/serialize-example")
    @ResponseBody
    public String serializeExample(@RequestParam String message) {
        try {
            SimpleObject obj = new SimpleObject(message);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(obj);
            oos.close();

            byte[] serialized = bos.toByteArray();
            String encoded = Base64.getEncoder().encodeToString(serialized);

            return "Objet sérialisé (Base64): " + encoded;
        } catch (Exception e) {
            return "Erreur: " + e.getMessage();
        }
    }

    private String getStackTrace(Exception e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    /**
     * Classe exemple pour la sérialisation
     */
    static class SimpleObject implements Serializable {
        private static final long serialVersionUID = 1L;
        private String message;

        public SimpleObject(String message) {
            this.message = message;
        }

        @Override
        public String toString() {
            return "SimpleObject{message='" + message + "'}";
        }
    }

    /**
     * VULNÉRABILITÉ: Classe avec méthode readObject malveillante
     * Cette classe démontre comment la désérialisation peut exécuter du code
     */
    static class MaliciousObject implements Serializable {
        private static final long serialVersionUID = 1L;
        private String command;

        public MaliciousObject(String command) {
            this.command = command;
        }

        // Cette méthode est appelée automatiquement lors de la désérialisation
        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // VULNÉRABILITÉ: Exécution de commande lors de la désérialisation
            try {
                Runtime.getRuntime().exec(command);
            } catch (Exception e) {
                // Silencieux
            }
        }
    }
}
