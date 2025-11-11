package com.vulnerable.app.service;

import com.vulnerable.app.model.User;
import org.springframework.stereotype.Service;

/**
 * Service d'authentification avec vulnérabilités
 */
@Service
public class AuthService {

    /**
     * VULNÉRABILITÉ: Authentification faible
     * Pas de hashing, pas de salt
     */
    public boolean authenticate(String username, String password, User user) {
        // VULNÉRABILITÉ: Comparaison directe de mot de passe en clair
        return user != null && user.getPassword().equals(password);
    }

    /**
     * VULNÉRABILITÉ: Pas de vérification de force du mot de passe
     */
    public boolean isPasswordStrong(String password) {
        // Retourne toujours true - pas de validation
        return true;
    }

    /**
     * VULNÉRABILITÉ: Génération de token prévisible
     */
    public String generateSessionToken(String username) {
        // VULNÉRABILITÉ: Token basé sur l'heure actuelle (prévisible)
        return username + "_" + System.currentTimeMillis();
    }
}
