package com.vulnerable.app.controller;

import com.vulnerable.app.model.User;
import com.vulnerable.app.service.AuthService;
import com.vulnerable.app.service.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.Date;

/**
 * VULNÉRABILITÉ: A07:2021 - Identification and Authentication Failures
 */
@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private UserService userService;

    // VULNÉRABILITÉ: Clé secrète hard-codée et faible
    private static final String SECRET_KEY = "secret";

    /**
     * VULNÉRABILITÉ: Authentification faible
     * - Pas de limite de tentatives
     * - Pas de CAPTCHA
     * - Messages d'erreur informatifs qui révèlent si l'utilisateur existe
     */
    @PostMapping("/login")
    @ResponseBody
    public String login(@RequestParam String username,
                       @RequestParam String password,
                       HttpServletResponse response,
                       HttpSession session) {
        try {
            User user = userService.findByUsername(username);

            if (user == null) {
                // VULNÉRABILITÉ: Message qui confirme que l'utilisateur n'existe pas
                return "Erreur: L'utilisateur '" + username + "' n'existe pas";
            }

            // VULNÉRABILITÉ: Comparaison de mot de passe en clair
            if (!user.getPassword().equals(password)) {
                return "Erreur: Mot de passe incorrect pour l'utilisateur '" + username + "'";
            }

            // VULNÉRABILITÉ: JWT avec algorithme faible et clé secrète faible
            String token = Jwts.builder()
                    .setSubject(username)
                    .claim("role", user.getRole())
                    .setIssuedAt(new Date())
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                    .compact();

            // VULNÉRABILITÉ: Cookie sans flags HttpOnly et Secure
            Cookie cookie = new Cookie("auth_token", token);
            cookie.setMaxAge(3600);
            cookie.setPath("/");
            // Pas de cookie.setHttpOnly(true)
            // Pas de cookie.setSecure(true)
            response.addCookie(cookie);

            // VULNÉRABILITÉ: Session fixation - pas de régénération de l'ID de session
            session.setAttribute("user", username);
            session.setAttribute("role", user.getRole());

            return "Connexion réussie! Token: " + token;

        } catch (SQLException e) {
            return "Erreur de base de données: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Inscription sans validation
     * - Pas de vérification de force du mot de passe
     * - Pas de vérification d'email
     * - Pas de CSRF protection
     */
    @PostMapping("/register")
    @ResponseBody
    public String register(@RequestParam String username,
                          @RequestParam String password,
                          @RequestParam String email) {
        try {
            // VULNÉRABILITÉ: Stockage du mot de passe en clair
            User user = new User();
            user.setUsername(username);
            user.setPassword(password); // Pas de hashing!
            user.setEmail(email);
            user.setRole("user");

            userService.createUser(user);

            return "Utilisateur créé avec succès! Username: " + username;
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Réinitialisation de mot de passe sans vérification
     */
    @PostMapping("/reset-password")
    @ResponseBody
    public String resetPassword(@RequestParam String username,
                               @RequestParam String newPassword) {
        try {
            // VULNÉRABILITÉ: Pas de vérification d'identité
            // Pas de token de réinitialisation
            // Pas d'envoi d'email
            User user = userService.findByUsername(username);
            if (user != null) {
                user.setPassword(newPassword); // Stockage en clair
                userService.updateUser(user);
                return "Mot de passe réinitialisé pour " + username;
            }
            return "Utilisateur non trouvé";
        } catch (SQLException e) {
            return "Erreur: " + e.getMessage();
        }
    }

    /**
     * VULNÉRABILITÉ: Pas de déconnexion appropriée
     */
    @GetMapping("/logout")
    @ResponseBody
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // VULNÉRABILITÉ: Le token JWT reste valide
        // Pas d'invalidation de session côté serveur
        Cookie cookie = new Cookie("auth_token", "");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return "Déconnecté (mais le token reste valide!)";
    }
}
