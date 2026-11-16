package com.mitre.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class TechniqueExtractor implements ExtractorStrategy {

    @Override
    public String getStrategyName() {
        return "Rule-Based Keyword Matching";
    }

    @Override
    public List<Technique> extractTechniques(String text) {
        List<Technique> detected = new ArrayList<>();

        if (text == null || text.isBlank()) {
            return detected;
        }

        // Split the report into clean sentences
        String[] sentences = text.split("(?<=[.!?])\\s+");

        // Flags so we don't add duplicate techniques for the same report
        boolean foundPowerShell = false;
        boolean foundCmd = false;
        boolean foundScheduledTask = false;
        boolean foundCredentialDumping = false;
        boolean foundC2 = false;

        for (String rawSentence : sentences) {
            String sentence = rawSentence.trim().replaceAll("\\s+", " ");
            String lower = sentence.toLowerCase(Locale.ROOT);

            // 1. PowerShell Detection
            if (!foundPowerShell && (lower.contains("powershell") || lower.contains("invoke-expression"))) {
                double score = (lower.contains("powershell") && lower.contains("invoke-expression")) ? 0.95 : 0.80;
                detected.add(new Technique(
                    "T1059.001",
                    "PowerShell",
                    "Execution",
                    "Adversaries may abuse PowerShell commands and scripts.",
                    sentence,
                    score
                ));
                foundPowerShell = true;
            }

            // 2. Windows Command Shell Detection
            if (!foundCmd && (lower.contains("cmd.exe") || lower.contains("command prompt"))) {
                detected.add(new Technique(
                    "T1059.003",
                    "Windows Command Shell",
                    "Execution",
                    "Adversaries may abuse the Windows command shell.",
                    sentence,
                    0.80
                ));
                foundCmd = true;
            }

            // 3. Scheduled Task Detection
            if (!foundScheduledTask && (lower.contains("scheduled task") || lower.contains("schtasks"))) {
                detected.add(new Technique(
                    "T1053.005",
                    "Scheduled Task",
                    "Persistence",
                    "Adversaries may use scheduled tasks to maintain persistence.",
                    sentence,
                    0.85
                ));
                foundScheduledTask = true;
            }

            // 4. Credential Dumping Detection
            if (!foundCredentialDumping && (lower.contains("mimikatz") || lower.contains("lsass") || lower.contains("credential dumping"))) {
                int matches = 0;
                if (lower.contains("mimikatz")) matches++;
                if (lower.contains("lsass")) matches++;
                if (lower.contains("credential dumping")) matches++;
                double score = (matches >= 2) ? 0.95 : 0.80;

                detected.add(new Technique(
                    "T1003",
                    "OS Credential Dumping",
                    "Credential Access",
                    "Adversaries may attempt to dump credentials from operating systems.",
                    sentence,
                    score
                ));
                foundCredentialDumping = true;
            }

            // 5. Application Layer Protocol Detection
            if (!foundC2 && (lower.contains("http beacon") || lower.contains("command and control") || lower.contains("c2"))) {
                detected.add(new Technique(
                    "T1071",
                    "Application Layer Protocol",
                    "Command and Control",
                    "Adversaries may communicate using application layer protocols.",
                    sentence,
                    0.80
                ));
                foundC2 = true;
            }
        }

        return detected;
    }
}