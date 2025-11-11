package com.vulnerable.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * VULNÉRABILITÉS MULTIPLES:
 * - A01:2021 - Broken Access Control
 * - A05:2021 - Security Misconfiguration
 * - Path Traversal
 */
@Controller
@RequestMapping("/file")
public class FileController {

    private static final String UPLOAD_DIR = "/tmp/uploads/";

    /**
     * VULNÉRABILITÉ: Path Traversal / Directory Traversal
     * Le nom de fichier n'est pas validé
     */
    @GetMapping("/download")
    public void downloadFile(@RequestParam String filename, HttpServletResponse response) {
        try {
            // VULNÉRABILITÉ: Pas de validation du nom de fichier
            // Un attaquant peut utiliser "../" pour accéder à n'importe quel fichier
            File file = new File(UPLOAD_DIR + filename);

            if (file.exists()) {
                response.setContentType("application/octet-stream");
                response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

                Files.copy(file.toPath(), response.getOutputStream());
                response.getOutputStream().flush();
            } else {
                response.getWriter().write("Fichier non trouvé: " + file.getAbsolutePath());
            }
        } catch (IOException e) {
            try {
                response.getWriter().write("Erreur: " + e.getMessage());
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    /**
     * VULNÉRABILITÉ: Unrestricted File Upload
     * - Pas de validation du type de fichier
     * - Pas de limite de taille
     * - Pas de scan antivirus
     */
    @PostMapping("/upload")
    @ResponseBody
    public String uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            // Création du répertoire s'il n'existe pas
            new File(UPLOAD_DIR).mkdirs();

            // VULNÉRABILITÉ: Pas de validation du type de fichier
            // Un attaquant peut uploader un fichier .jsp ou .class
            String filename = file.getOriginalFilename();

            // VULNÉRABILITÉ: Pas de validation ou sanitization du nom de fichier
            File dest = new File(UPLOAD_DIR + filename);

            file.transferTo(dest);

            return "Fichier uploadé avec succès: " + filename +
                   "<br>Chemin: " + dest.getAbsolutePath();
        } catch (IOException e) {
            return "Erreur lors de l'upload: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Arbitrary File Read
     */
    @GetMapping("/read")
    @ResponseBody
    public String readFile(@RequestParam String path) {
        try {
            // VULNÉRABILITÉ: Pas de validation du chemin
            // Un attaquant peut lire /etc/passwd, /etc/shadow, etc.
            BufferedReader reader = new BufferedReader(new FileReader(path));
            StringBuilder content = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();

            return "<pre>" + content.toString() + "</pre>";
        } catch (IOException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Command Injection via filename
     */
    @GetMapping("/convert")
    @ResponseBody
    public String convertFile(@RequestParam String filename) {
        try {
            // VULNÉRABILITÉ: Command Injection
            // Un attaquant peut injecter des commandes shell
            String command = "convert " + UPLOAD_DIR + filename + " " + UPLOAD_DIR + "converted_" + filename;

            Process process = Runtime.getRuntime().exec(command);
            process.waitFor();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            return "Conversion effectuée!<br><pre>" + output.toString() + "</pre>";
        } catch (Exception e) {
            return "Erreur: " + e.getMessage();
        }
    }
}
