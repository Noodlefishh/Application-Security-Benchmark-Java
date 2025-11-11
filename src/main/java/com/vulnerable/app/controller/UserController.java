package com.vulnerable.app.controller;

import com.vulnerable.app.model.User;
import com.vulnerable.app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.SQLException;
import java.util.List;

/**
 * VULNÉRABILITÉ: A03:2021 - Injection (SQL Injection)
 * Ce contrôleur contient intentionnellement des vulnérabilités d'injection SQL
 */
@Controller
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * VULNÉRABILITÉ: SQL Injection
     * Le paramètre 'username' est directement concaténé dans la requête SQL
     */
    @GetMapping("/search")
    @ResponseBody
    public String searchUser(@RequestParam String username) {
        try {
            List<User> users = userService.searchUserByUsername(username);
            StringBuilder response = new StringBuilder("<h2>Résultats de recherche:</h2><ul>");
            for (User user : users) {
                response.append("<li>").append(user.getUsername())
                        .append(" - ").append(user.getEmail()).append("</li>");
            }
            response.append("</ul>");
            return response.toString();
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: SQL Injection via ORDER BY
     */
    @GetMapping("/list")
    @ResponseBody
    public String listUsers(@RequestParam(required = false, defaultValue = "id") String sortBy) {
        try {
            List<User> users = userService.listUsers(sortBy);
            StringBuilder response = new StringBuilder("<h2>Liste des utilisateurs:</h2><ul>");
            for (User user : users) {
                response.append("<li>ID: ").append(user.getId())
                        .append(" - ").append(user.getUsername())
                        .append(" - ").append(user.getEmail()).append("</li>");
            }
            response.append("</ul>");
            return response.toString();
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: A01:2021 - Broken Access Control
     * Permet de voir le profil de n'importe quel utilisateur sans vérification
     */
    @GetMapping("/profile/{userId}")
    @ResponseBody
    public String viewProfile(@PathVariable int userId) {
        try {
            User user = userService.getUserById(userId);
            if (user != null) {
                return "<h2>Profil utilisateur</h2>" +
                        "<p>ID: " + user.getId() + "</p>" +
                        "<p>Username: " + user.getUsername() + "</p>" +
                        "<p>Email: " + user.getEmail() + "</p>" +
                        "<p>Password Hash: " + user.getPassword() + "</p>" +
                        "<p>Role: " + user.getRole() + "</p>" +
                        "<p>SSN: " + user.getSsn() + "</p>";
            }
            return "Utilisateur non trouvé";
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: A03:2021 - Cross-Site Scripting (XSS)
     * Le contenu utilisateur est affiché sans échappement
     */
    @GetMapping("/comment")
    @ResponseBody
    public String addComment(@RequestParam String comment, @RequestParam String username) {
        return "<h2>Commentaire ajouté</h2>" +
                "<p>Utilisateur: " + username + "</p>" +
                "<p>Commentaire: " + comment + "</p>";
    }

    /**
     * VULNÉRABILITÉ: A02:2021 - Cryptographic Failures
     * Affiche des informations sensibles en clair
     */
    @GetMapping("/admin/export")
    @ResponseBody
    public String exportUsers() {
        try {
            List<User> users = userService.getAllUsers();
            StringBuilder csv = new StringBuilder("ID,Username,Email,Password,SSN,CreditCard\n");
            for (User user : users) {
                csv.append(user.getId()).append(",")
                   .append(user.getUsername()).append(",")
                   .append(user.getEmail()).append(",")
                   .append(user.getPassword()).append(",")
                   .append(user.getSsn()).append(",")
                   .append(user.getCreditCard()).append("\n");
            }
            return csv.toString();
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }
}
