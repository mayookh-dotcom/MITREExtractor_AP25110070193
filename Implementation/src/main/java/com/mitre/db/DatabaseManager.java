package com.mitre.db;

import com.mitre.analyzer.Technique;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class DatabaseManager {

    private static final String DB_URL = "jdbc:sqlite:mitre_history.db";

    public DatabaseManager() {
        initializeDatabase();
    }

    // CREATE TABLE if it does not exist yet
    private void initializeDatabase() {
        String sql = """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_name TEXT NOT NULL,
                method_used TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                technique_name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                confidence REAL NOT NULL,
                evidence TEXT,
                analyzed_at TEXT NOT NULL
            );
            """;

        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            System.err.println("Database initialization error: " + e.getMessage());
        }
    }

    // CREATE (Insert) detected techniques into SQLite
    public void saveAnalysis(String reportName, String methodUsed, List<Technique> techniques) {
        String insertSql = """
            INSERT INTO analysis_history
            (report_name, method_used, technique_id, technique_name, tactic, confidence, evidence, analyzed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """;

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(insertSql)) {

            for (Technique t : techniques) {
                pstmt.setString(1, reportName);
                pstmt.setString(2, methodUsed);
                pstmt.setString(3, t.getId());
                pstmt.setString(4, t.getName());
                pstmt.setString(5, t.getTactic());
                pstmt.setDouble(6, t.getConfidenceScore());
                pstmt.setString(7, t.getEvidence());
                pstmt.setString(8, timestamp);
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException e) {
            System.err.println("Error saving analysis to SQLite: " + e.getMessage());
        }
    }

    // READ (Select) recent analysis history
    public List<String> getRecentHistory(int limit) {
        List<String> records = new ArrayList<>();
        String query = "SELECT analyzed_at, report_name, method_used, technique_id, technique_name, confidence " +
                       "FROM analysis_history ORDER BY id DESC LIMIT ?;";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(query)) {

            pstmt.setInt(1, limit);
            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                int confPct = (int) Math.round(rs.getDouble("confidence") * 100);
                String row = String.format("[%s] %s | %s -> %s (%s) - %d%%",
                    rs.getString("analyzed_at"),
                    rs.getString("report_name"),
                    rs.getString("method_used"),
                    rs.getString("technique_id"),
                    rs.getString("technique_name"),
                    confPct
                );
                records.add(row);
            }
        } catch (SQLException e) {
            System.err.println("Error reading history: " + e.getMessage());
        }
        return records;
    }

    // DELETE all history records
    public void clearHistory() {
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM analysis_history;");
        } catch (SQLException e) {
            System.err.println("Error clearing history: " + e.getMessage());
        }
    }
}