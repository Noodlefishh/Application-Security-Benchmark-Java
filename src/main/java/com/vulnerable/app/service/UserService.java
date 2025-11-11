package com.vulnerable.app.service;

import com.vulnerable.app.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Service utilisateur avec vulnérabilités SQL Injection
 */
@Service
public class UserService {

    @Autowired
    private DataSource dataSource;

    /**
     * VULNÉRABILITÉ: SQL Injection
     * Utilise la concaténation de chaînes au lieu de PreparedStatement
     */
    public List<User> searchUserByUsername(String username) throws SQLException {
        List<User> users = new ArrayList<>();
        Connection conn = dataSource.getConnection();

        // VULNÉRABILITÉ: Concaténation SQL directe
        String query = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            users.add(extractUser(rs));
        }

        rs.close();
        stmt.close();
        conn.close();

        return users;
    }

    /**
     * VULNÉRABILITÉ: SQL Injection via ORDER BY
     */
    public List<User> listUsers(String sortBy) throws SQLException {
        List<User> users = new ArrayList<>();
        Connection conn = dataSource.getConnection();

        // VULNÉRABILITÉ: ORDER BY non sécurisé
        String query = "SELECT * FROM users ORDER BY " + sortBy;

        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            users.add(extractUser(rs));
        }

        rs.close();
        stmt.close();
        conn.close();

        return users;
    }

    public User getUserById(int id) throws SQLException {
        Connection conn = dataSource.getConnection();

        // Cette fois-ci, utilisation correcte (pour comparaison)
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setInt(1, id);

        ResultSet rs = pstmt.executeQuery();
        User user = null;

        if (rs.next()) {
            user = extractUser(rs);
        }

        rs.close();
        pstmt.close();
        conn.close();

        return user;
    }

    public List<User> getAllUsers() throws SQLException {
        List<User> users = new ArrayList<>();
        Connection conn = dataSource.getConnection();

        String query = "SELECT * FROM users";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            users.add(extractUser(rs));
        }

        rs.close();
        stmt.close();
        conn.close();

        return users;
    }

    public User findByUsername(String username) throws SQLException {
        Connection conn = dataSource.getConnection();

        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, username);

        ResultSet rs = pstmt.executeQuery();
        User user = null;

        if (rs.next()) {
            user = extractUser(rs);
        }

        rs.close();
        pstmt.close();
        conn.close();

        return user;
    }

    public void createUser(User user) throws SQLException {
        Connection conn = dataSource.getConnection();

        String query = "INSERT INTO users (username, password, email, role, ssn, credit_card) VALUES (?, ?, ?, ?, ?, ?)";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, user.getUsername());
        pstmt.setString(2, user.getPassword()); // VULNÉRABILITÉ: Mot de passe en clair
        pstmt.setString(3, user.getEmail());
        pstmt.setString(4, user.getRole());
        pstmt.setString(5, user.getSsn());
        pstmt.setString(6, user.getCreditCard());

        pstmt.executeUpdate();

        pstmt.close();
        conn.close();
    }

    public void updateUser(User user) throws SQLException {
        Connection conn = dataSource.getConnection();

        String query = "UPDATE users SET password = ?, email = ?, role = ? WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, user.getPassword());
        pstmt.setString(2, user.getEmail());
        pstmt.setString(3, user.getRole());
        pstmt.setString(4, user.getUsername());

        pstmt.executeUpdate();

        pstmt.close();
        conn.close();
    }

    private User extractUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getInt("id"));
        user.setUsername(rs.getString("username"));
        user.setPassword(rs.getString("password"));
        user.setEmail(rs.getString("email"));
        user.setRole(rs.getString("role"));
        user.setSsn(rs.getString("ssn"));
        user.setCreditCard(rs.getString("credit_card"));
        return user;
    }
}
