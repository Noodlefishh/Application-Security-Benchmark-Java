package com.vulnerable.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;

/**
 * Configuration Spring MVC
 * VULNÉRABILITÉ: A05:2021 - Security Misconfiguration
 */
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.vulnerable.app")
public class WebConfig implements WebMvcConfigurer {

    @Bean
    public DataSource dataSource() {
        // Base de données H2 en mémoire
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript("classpath:schema.sql")
                .addScript("classpath:data.sql")
                .build();
    }

    /**
     * VULNÉRABILITÉ: Configuration non sécurisée de l'upload de fichiers
     * Pas de limite de taille
     */
    @Bean
    public CommonsMultipartResolver multipartResolver() {
        CommonsMultipartResolver resolver = new CommonsMultipartResolver();
        // VULNÉRABILITÉ: Pas de limite de taille
        resolver.setMaxUploadSize(-1);
        resolver.setMaxInMemorySize(-1);
        return resolver;
    }

    // VULNÉRABILITÉ: Pas de configuration CORS sécurisée
    // VULNÉRABILITÉ: Pas de Content Security Policy
    // VULNÉRABILITÉ: Pas de headers de sécurité (X-Frame-Options, X-XSS-Protection, etc.)
}
