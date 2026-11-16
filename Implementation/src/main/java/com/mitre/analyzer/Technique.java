package com.mitre.analyzer;

public class Technique {
    private String id;
    private String name;
    private String tactic;
    private String description;
    private String evidence;
    private double confidenceScore;

    // Constructor with evidence and confidence score
    public Technique(String id, String name, String tactic, String description, String evidence, double confidenceScore) {
        this.id = id;
        this.name = name;
        this.tactic = tactic;
        this.description = description;
        this.evidence = evidence;
        this.confidenceScore = confidenceScore;
    }

    // Getters
    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getTactic() {
        return tactic;
    }

    public String getDescription() {
        return description;
    }

    public String getEvidence() {
        return evidence;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }
}