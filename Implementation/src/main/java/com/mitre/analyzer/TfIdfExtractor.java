package com.mitre.analyzer;

import java.util.*;
import java.util.stream.Collectors;

public class TfIdfExtractor implements ExtractorStrategy {

    // Internal record representing a MITRE ATT&CK reference entry
    private static class AttackDefinition {
        final String id;
        final String name;
        final String tactic;
        final String description;
        final String referenceProfile;

        AttackDefinition(String id, String name, String tactic, String description, String referenceProfile) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.description = description;
            this.referenceProfile = referenceProfile;
        }
    }

    private static final Set<String> STOP_WORDS = Set.of(
        "the", "and", "to", "of", "a", "in", "for", "on", "with", "as", "by", "an", "be", "is", "was", "were", "that", "from", "at", "or"
    );

    private final List<AttackDefinition> knowledgeBase;
    private final Map<String, Double> idfMap;

    public TfIdfExtractor() {
        this.knowledgeBase = buildKnowledgeBase();
        this.idfMap = computeIdf(this.knowledgeBase);
    }

    @Override
    public String getStrategyName() {
        return "TF-IDF Cosine Similarity Retrieval";
    }

    @Override
    public List<Technique> extractTechniques(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        String[] sentences = text.split("(?<=[.!?])\\s+");
        Map<String, Technique> bestMatches = new LinkedHashMap<>();

        for (String rawSentence : sentences) {
            String sentence = rawSentence.trim().replaceAll("\\s+", " ");
            List<String> sentenceTokens = tokenize(sentence);
            if (sentenceTokens.isEmpty()) continue;

            Map<String, Double> sentenceVector = computeTfIdfVector(sentenceTokens);

            for (AttackDefinition def : knowledgeBase) {
                Map<String, Double> defVector = computeTfIdfVector(tokenize(def.referenceProfile));
                double similarity = cosineSimilarity(sentenceVector, defVector);

                // Threshold: keep meaningful semantic/statistical overlaps
                if (similarity >= 0.15) {
                    double normalizedConfidence = Math.min(0.98, Math.round((0.50 + similarity) * 100.0) / 100.0);
                    Technique existing = bestMatches.get(def.id);

                    // Keep the highest-scoring evidence sentence for each technique
                    if (existing == null || normalizedConfidence > existing.getConfidenceScore()) {
                        bestMatches.put(def.id, new Technique(
                            def.id,
                            def.name,
                            def.tactic,
                            def.description,
                            sentence,
                            normalizedConfidence
                        ));
                    }
                }
            }
        }

        // Java Stream: sort detected techniques from highest confidence to lowest
        return bestMatches.values().stream()
            .sorted(Comparator.comparingDouble(Technique::getConfidenceScore).reversed())
            .collect(Collectors.toList());
    }

    private List<String> tokenize(String input) {
        return Arrays.stream(input.toLowerCase(Locale.ROOT).split("[^a-z0-9.]+"))
            .filter(token -> token.length() > 2 && !STOP_WORDS.contains(token))
            .collect(Collectors.toList());
    }

    private Map<String, Double> computeIdf(List<AttackDefinition> docs) {
        Map<String, Integer> docFreq = new HashMap<>();
        for (AttackDefinition doc : docs) {
            Set<String> uniqueTerms = new HashSet<>(tokenize(doc.referenceProfile));
            for (String term : uniqueTerms) {
                docFreq.put(term, docFreq.getOrDefault(term, 0) + 1);
            }
        }

        Map<String, Double> idf = new HashMap<>();
        int totalDocs = docs.size();
        for (Map.Entry<String, Integer> entry : docFreq.entrySet()) {
            idf.put(entry.getKey(), Math.log((double) totalDocs / entry.getValue()) + 1.0);
        }
        return idf;
    }

    private Map<String, Double> computeTfIdfVector(List<String> tokens) {
        Map<String, Long> termCounts = tokens.stream()
            .collect(Collectors.groupingBy(t -> t, Collectors.counting()));

        Map<String, Double> vector = new HashMap<>();
        for (Map.Entry<String, Long> entry : termCounts.entrySet()) {
            double tf = (double) entry.getValue() / tokens.size();
            double idf = idfMap.getOrDefault(entry.getKey(), 1.0);
            vector.put(entry.getKey(), tf * idf);
        }
        return vector;
    }

    private double cosineSimilarity(Map<String, Double> v1, Map<String, Double> v2) {
        double dotProduct = 0.0;
        double norm1 = 0.0;
        double norm2 = 0.0;

        for (double val : v1.values()) norm1 += val * val;
        for (double val : v2.values()) norm2 += val * val;

        for (Map.Entry<String, Double> entry : v1.entrySet()) {
            if (v2.containsKey(entry.getKey())) {
                dotProduct += entry.getValue() * v2.get(entry.getKey());
            }
        }

        if (norm1 == 0.0 || norm2 == 0.0) return 0.0;
        return dotProduct / (Math.sqrt(norm1) * Math.sqrt(norm2));
    }

    private List<AttackDefinition> buildKnowledgeBase() {
        return List.of(
            new AttackDefinition(
                "T1059.001", "PowerShell", "Execution",
                "Adversaries may abuse PowerShell commands and scripts.",
                "powershell invoke-expression script execution malicious commands encodedcommand payload download"
            ),
            new AttackDefinition(
                "T1059.003", "Windows Command Shell", "Execution",
                "Adversaries may abuse the Windows command shell.",
                "cmd.exe command prompt batch script shell execution terminal"
            ),
            new AttackDefinition(
                "T1053.005", "Scheduled Task", "Persistence",
                "Adversaries may use scheduled tasks to maintain persistence.",
                "scheduled task schtasks cron timer persistence startup recurring execution"
            ),
            new AttackDefinition(
                "T1003", "OS Credential Dumping", "Credential Access",
                "Adversaries may attempt to dump credentials from operating systems.",
                "mimikatz lsass credential dumping password hashes memory dump sam ntds"
            ),
            new AttackDefinition(
                "T1071", "Application Layer Protocol", "Command and Control",
                "Adversaries may communicate using application layer protocols.",
                "http beacon https dns command and control c2 server network communication exfiltration"
            ),
            new AttackDefinition(
                "T1566.001", "Spearphishing Attachment", "Initial Access",
                "Adversaries may send spearphishing emails with a malicious attachment.",
                "phishing email spearphishing malicious attachment macro document lure victim"
            )
        );
    }
}