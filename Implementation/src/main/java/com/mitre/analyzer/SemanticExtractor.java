package com.mitre.analyzer;

import java.util.*;
import java.util.stream.Collectors;

public class SemanticExtractor implements ExtractorStrategy {

    // Represents an ATT&CK technique along with semantic concept clusters (synonym groups)
    private static class SemanticTechniqueProfile {
        final String id;
        final String name;
        final String tactic;
        final String description;
        final List<Set<String>> conceptClusters;

        SemanticTechniqueProfile(String id, String name, String tactic, String description, List<Set<String>> conceptClusters) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.description = description;
            this.conceptClusters = conceptClusters;
        }
    }

    private final List<SemanticTechniqueProfile> profiles;

    public SemanticExtractor() {
        this.profiles = buildSemanticProfiles();
    }

    @Override
    public String getStrategyName() {
        return "Semantic Concept Embedding Retrieval";
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
            Set<String> tokens = tokenize(sentence);
            if (tokens.isEmpty()) continue;

            for (SemanticTechniqueProfile profile : profiles) {
                double semanticScore = computeSemanticSimilarity(tokens, profile.conceptClusters);

                if (semanticScore >= 0.35) {
                    double confidence = Math.min(0.99, Math.round((0.55 + semanticScore * 0.45) * 100.0) / 100.0);
                    Technique existing = bestMatches.get(profile.id);

                    if (existing == null || confidence > existing.getConfidenceScore()) {
                        bestMatches.put(profile.id, new Technique(
                            profile.id,
                            profile.name,
                            profile.tactic,
                            profile.description,
                            sentence,
                            confidence
                        ));
                    }
                }
            }
        }

        return bestMatches.values().stream()
            .sorted(Comparator.comparingDouble(Technique::getConfidenceScore).reversed())
            .collect(Collectors.toList());
    }

    private double computeSemanticSimilarity(Set<String> sentenceTokens, List<Set<String>> conceptClusters) {
        int matchedClusters = 0;
        for (Set<String> cluster : conceptClusters) {
            boolean clusterHit = sentenceTokens.stream().anyMatch(cluster::contains);
            if (clusterHit) {
                matchedClusters++;
            }
        }
        return (double) matchedClusters / conceptClusters.size();
    }

    private Set<String> tokenize(String text) {
        return Arrays.stream(text.toLowerCase(Locale.ROOT).split("[^a-z0-9.]+"))
            .filter(t -> t.length() > 2)
            .collect(Collectors.toSet());
    }

    private List<SemanticTechniqueProfile> buildSemanticProfiles() {
        return List.of(
            new SemanticTechniqueProfile(
                "T1059.001", "PowerShell", "Execution",
                "Adversaries may abuse PowerShell commands and scripts.",
                List.of(
                    Set.of("powershell", "script", "encodedcommand", "invoke", "cmdlet"),
                    Set.of("execute", "executed", "execution", "download", "payload", "malicious", "run")
                )
            ),
            new SemanticTechniqueProfile(
                "T1059.003", "Windows Command Shell", "Execution",
                "Adversaries may abuse the Windows command shell.",
                List.of(
                    Set.of("cmd", "cmd.exe", "command", "prompt", "batch", "shell", "terminal"),
                    Set.of("execute", "executed", "spawned", "launched", "script", "binary")
                )
            ),
            new SemanticTechniqueProfile(
                "T1053.005", "Scheduled Task", "Persistence",
                "Adversaries may use scheduled tasks to maintain persistence.",
                List.of(
                    Set.of("scheduled", "task", "schtasks", "cron", "timer", "startup", "boot", "logon"),
                    Set.of("persistence", "persist", "recurring", "automatically", "maintain", "reboot")
                )
            ),
            new SemanticTechniqueProfile(
                "T1003", "OS Credential Dumping", "Credential Access",
                "Adversaries may attempt to dump credentials from operating systems.",
                List.of(
                    Set.of("mimikatz", "lsass", "credential", "credentials", "password", "hashes", "ntlm", "sam"),
                    Set.of("dump", "dumping", "harvest", "harvested", "extract", "extracted", "memory", "steal")
                )
            ),
            new SemanticTechniqueProfile(
                "T1071", "Application Layer Protocol", "Command and Control",
                "Adversaries may communicate using application layer protocols.",
                List.of(
                    Set.of("http", "https", "dns", "beacon", "beaconing", "web", "traffic", "outbound"),
                    Set.of("c2", "command", "control", "server", "exfiltrate", "exfiltration", "callback", "remote")
                )
            ),
            new SemanticTechniqueProfile(
                "T1566.001", "Spearphishing Attachment", "Initial Access",
                "Adversaries may send spearphishing emails with a malicious attachment.",
                List.of(
                    Set.of("phishing", "spearphishing", "email", "mail", "lure", "inbox"),
                    Set.of("attachment", "macro", "document", "pdf", "docx", "opened", "clicked")
                )
            )
        );
    }
}