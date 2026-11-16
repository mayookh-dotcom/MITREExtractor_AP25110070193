package com.mitre.eval;

import com.mitre.analyzer.ExtractorStrategy;
import com.mitre.analyzer.Technique;

import java.util.*;
import java.util.stream.Collectors;

public class EvaluationBenchmark {

    // Represents one ground-truth annotated threat report sample
    public static class TestSample {
        final String id;
        final String text;
        final Set<String> expectedTechniqueIds;

        public TestSample(String id, String text, Set<String> expectedTechniqueIds) {
            this.id = id;
            this.text = text;
            this.expectedTechniqueIds = expectedTechniqueIds;
        }
    }

    // Holds computed research metrics for one ExtractorStrategy
    public static class EvaluationResult {
        public final String methodName;
        public final double precision;
        public final double recall;
        public final double f1Score;
        public final double top1Accuracy;
        public final double mrr;

        public EvaluationResult(String methodName, double precision, double recall, double f1Score, double top1Accuracy, double mrr) {
            this.methodName = methodName;
            this.precision = precision;
            this.recall = recall;
            this.f1Score = f1Score;
            this.top1Accuracy = top1Accuracy;
            this.mrr = mrr;
        }
    }

    // Ground-truth annotated test set (combining exact terms & paraphrased CTI descriptions)
    public List<TestSample> getAnnotatedTestSet() {
        return List.of(
            new TestSample(
                "CTI-01",
                "The attacker gained access to the system and executed malicious PowerShell commands. " +
                "The attacker used Mimikatz for credential dumping and accessed LSASS memory.",
                Set.of("T1059.001", "T1003")
            ),
            new TestSample(
                "CTI-02",
                "The adversary created a scheduled task to maintain persistence across system reboots. " +
                "HTTP beacon communication was observed between the compromised host and the C2 server.",
                Set.of("T1053.005", "T1071")
            ),
            new TestSample(
                "CTI-03",
                "Victims received a spearphishing email containing a malicious attachment with an embedded macro. " +
                "Opening the document spawned cmd.exe to execute a batch script.",
                Set.of("T1566.001", "T1059.003")
            ),
            new TestSample(
                "CTI-04",
                "To harvest password hashes from memory, the intrusion operator extracted NTLM credentials. " +
                "The payload configured automatic startup at user logon to persist on the endpoint.",
                Set.of("T1003", "T1053.005")
            ),
            new TestSample(
                "CTI-05",
                "Outbound web traffic periodically sent callback requests to a remote server for exfiltration. " +
                "An encoded script payload was invoked directly in memory.",
                Set.of("T1071", "T1059.001")
            )
        );
    }

    public EvaluationResult evaluateStrategy(ExtractorStrategy strategy) {
        List<TestSample> dataset = getAnnotatedTestSet();

        int totalTruePositives = 0;
        int totalFalsePositives = 0;
        int totalFalseNegatives = 0;
        int top1Hits = 0;
        double reciprocalRankSum = 0.0;

        for (TestSample sample : dataset) {
            List<Technique> predictions = strategy.extractTechniques(sample.text);
            List<String> predictedIds = predictions.stream()
                .map(Technique::getId)
                .distinct()
                .collect(Collectors.toList());

            Set<String> predictedSet = new HashSet<>(predictedIds);

            // True Positives, False Positives, False Negatives
            for (String pred : predictedSet) {
                if (sample.expectedTechniqueIds.contains(pred)) {
                    totalTruePositives++;
                } else {
                    totalFalsePositives++;
                }
            }
            for (String expected : sample.expectedTechniqueIds) {
                if (!predictedSet.contains(expected)) {
                    totalFalseNegatives++;
                }
            }

            // Top-1 Accuracy: is the highest-ranked prediction in the ground truth?
            if (!predictedIds.isEmpty() && sample.expectedTechniqueIds.contains(predictedIds.get(0))) {
                top1Hits++;
            }

            // Mean Reciprocal Rank (MRR): rank of first relevant technique
            for (int i = 0; i < predictedIds.size(); i++) {
                if (sample.expectedTechniqueIds.contains(predictedIds.get(i))) {
                    reciprocalRankSum += 1.0 / (i + 1);
                    break;
                }
            }
        }

        double precision = (totalTruePositives + totalFalsePositives == 0) ? 0.0
            : (double) totalTruePositives / (totalTruePositives + totalFalsePositives);

        double recall = (totalTruePositives + totalFalseNegatives == 0) ? 0.0
            : (double) totalTruePositives / (totalTruePositives + totalFalseNegatives);

        double f1 = (precision + recall == 0) ? 0.0
            : (2 * precision * recall) / (precision + recall);

        double top1Acc = (double) top1Hits / dataset.size();
        double mrr = reciprocalRankSum / dataset.size();

        return new EvaluationResult(strategy.getStrategyName(), precision, recall, f1, top1Acc, mrr);
    }
}