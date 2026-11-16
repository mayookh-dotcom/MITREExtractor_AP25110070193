package com.mitre.ui;

import com.mitre.analyzer.ExtractorStrategy;
import com.mitre.analyzer.SemanticExtractor;
import com.mitre.analyzer.Technique;
import com.mitre.analyzer.TechniqueExtractor;
import com.mitre.analyzer.TfIdfExtractor;
import com.mitre.db.DatabaseManager;
import com.mitre.eval.EvaluationBenchmark;
import com.mitre.eval.EvaluationBenchmark.EvaluationResult;
import com.mitre.parser.ReportParser;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.List;

public class MainFrame extends JFrame {

    private JTextArea textArea;
    private JLabel fileLabel;
    private JComboBox<String> strategyComboBox;
    private File selectedFile;

    private final ReportParser parser;
    private final ExtractorStrategy keywordStrategy;
    private final ExtractorStrategy tfidfStrategy;
    private final ExtractorStrategy semanticStrategy;
    private final DatabaseManager dbManager;
    private final EvaluationBenchmark benchmark;

    public MainFrame() {
        this.parser = new ReportParser();
        this.keywordStrategy = new TechniqueExtractor();
        this.tfidfStrategy = new TfIdfExtractor();
        this.semanticStrategy = new SemanticExtractor();
        this.dbManager = new DatabaseManager();
        this.benchmark = new EvaluationBenchmark();

        setTitle("Automatic MITRE ATT&CK Technique Extractor");
        setSize(1060, 680);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout(10, 10));

        // Top Panel: Upload, Algorithm Selector, Extract, Benchmark & DB History
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 10));
        JButton uploadButton = new JButton("Upload Report (PDF/TXT)");

        strategyComboBox = new JComboBox<>(new String[]{
            "Rule-Based Keyword Matching",
            "TF-IDF Cosine Similarity",
            "Semantic Concept Retrieval"
        });

        JButton extractButton = new JButton("Extract Techniques");
        JButton benchmarkButton = new JButton("Run Research Benchmark");
        JButton historyButton = new JButton("View History (DB)");
        JButton clearDbButton = new JButton("Clear History");
        fileLabel = new JLabel("No file selected");

        topPanel.add(uploadButton);
        topPanel.add(new JLabel("Method:"));
        topPanel.add(strategyComboBox);
        topPanel.add(extractButton);
        topPanel.add(benchmarkButton);
        topPanel.add(historyButton);
        topPanel.add(clearDbButton);
        topPanel.add(fileLabel);

        // Center Panel: Output display area
        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setMargin(new Insets(10, 10, 10, 10));

        JScrollPane scrollPane = new JScrollPane(textArea);

        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        // Button Actions
        uploadButton.addActionListener(e -> chooseFile());
        extractButton.addActionListener(e -> extractReportInBackground());
        benchmarkButton.addActionListener(e -> runResearchBenchmark());
        historyButton.addActionListener(e -> showDatabaseHistory());
        clearDbButton.addActionListener(e -> clearDatabaseHistory());
    }

    private void chooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.dir")));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
            fileLabel.setText("Selected: " + selectedFile.getName());
            textArea.setText("File loaded: " + selectedFile.getName() + "\nSelect a method and click 'Extract Techniques'.");
        }
    }

    private void extractReportInBackground() {
        if (selectedFile == null) {
            JOptionPane.showMessageDialog(
                this,
                "Please upload a report first.",
                "No File Selected",
                JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        ExtractorStrategy activeStrategy = switch (strategyComboBox.getSelectedIndex()) {
            case 1 -> tfidfStrategy;
            case 2 -> semanticStrategy;
            default -> keywordStrategy;
        };

        textArea.setText("Analysing " + selectedFile.getName() + " using " + activeStrategy.getStrategyName() + "...\nPlease wait.");

        SwingWorker<List<Technique>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<Technique> doInBackground() throws Exception {
                String extractedText = parser.extractText(selectedFile);
                if (extractedText == null || extractedText.isBlank()) {
                    return null;
                }
                List<Technique> detected = activeStrategy.extractTechniques(extractedText);
                if (!detected.isEmpty()) {
                    dbManager.saveAnalysis(selectedFile.getName(), activeStrategy.getStrategyName(), detected);
                }
                return detected;
            }

            @Override
            protected void done() {
                try {
                    List<Technique> detected = get();
                    if (detected == null) {
                        textArea.setText("No readable text found in the selected file.");
                        return;
                    }

                    StringBuilder results = new StringBuilder();
                    results.append("MITRE ATT&CK ANALYSIS RESULTS (Saved to SQLite DB)\n");
                    results.append("============================================================\n\n");
                    results.append("Report              : ").append(selectedFile.getName()).append("\n");
                    results.append("Extraction Method   : ").append(activeStrategy.getStrategyName()).append("\n");
                    results.append("Detected Techniques : ").append(detected.size()).append("\n\n");

                    if (detected.isEmpty()) {
                        results.append("No matching techniques found.");
                    } else {
                        for (Technique technique : detected) {
                            int confidencePercent = (int) Math.round(technique.getConfidenceScore() * 100);

                            results.append("Technique ID : ").append(technique.getId()).append("\n");
                            results.append("Name         : ").append(technique.getName()).append("\n");
                            results.append("Tactic       : ").append(technique.getTactic()).append("\n");
                            results.append("Confidence   : ").append(confidencePercent).append("%\n");
                            results.append("Evidence     : \"").append(technique.getEvidence()).append("\"\n");
                            results.append("Description  : ").append(technique.getDescription()).append("\n");
                            results.append("------------------------------------------------------------\n");
                        }
                    }

                    textArea.setText(results.toString());
                    textArea.setCaretPosition(0);

                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(
                        MainFrame.this,
                        "Error analysing report: " + ex.getMessage(),
                        "Analysis Error",
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        };

        worker.execute();
    }

    private void runResearchBenchmark() {
        List<ExtractorStrategy> strategies = List.of(keywordStrategy, tfidfStrategy, semanticStrategy);

        StringBuilder sb = new StringBuilder();
        sb.append("EXPERIMENTAL EVALUATION BENCHMARK (RQ1: Method Comparison)\n");
        sb.append("Dataset: Annotated CTI Threat Passages (N = 5 Samples, 10 Ground-Truth Techniques)\n");
        sb.append("=====================================================================================\n\n");
        sb.append(String.format("%-38s | %-9s | %-8s | %-8s | %-8s | %-6s\n",
            "Extraction Strategy", "Precision", "Recall", "F1-Score", "Top-1", "MRR"));
        sb.append("-------------------------------------------------------------------------------------\n");

        for (ExtractorStrategy strategy : strategies) {
            EvaluationResult res = benchmark.evaluateStrategy(strategy);
            sb.append(String.format("%-38s | %8.2f%% | %7.2f%% | %7.2f%% | %7.2f%% | %6.3f\n",
                res.methodName,
                res.precision * 100,
                res.recall * 100,
                res.f1Score * 100,
                res.top1Accuracy * 100,
                res.mrr
            ));
        }

        sb.append("-------------------------------------------------------------------------------------\n\n");
        sb.append("Key Research Takeaway (RQ1):\n");
        sb.append("- Rule-Based Keyword Matching achieves high precision on explicit tool names but misses\n");
        sb.append("  paraphrased attacker behaviors (lower recall).\n");
        sb.append("- Semantic Concept Retrieval significantly improves recall and MRR on unseen phrasing.\n");

        textArea.setText(sb.toString());
        textArea.setCaretPosition(0);
    }

    private void showDatabaseHistory() {
        List<String> history = dbManager.getRecentHistory(25);
        StringBuilder sb = new StringBuilder();
        sb.append("SQLITE ANALYSIS HISTORY (Most Recent 25 Detections)\n");
        sb.append("============================================================\n\n");

        if (history.isEmpty()) {
            sb.append("No analysis history found in database yet.\nRun an extraction first!");
        } else {
            for (String record : history) {
                sb.append(record).append("\n");
            }
        }

        textArea.setText(sb.toString());
        textArea.setCaretPosition(0);
    }

    private void clearDatabaseHistory() {
        int confirm = JOptionPane.showConfirmDialog(
            this,
            "Delete all saved analysis records from SQLite?",
            "Confirm Clear History",
            JOptionPane.YES_NO_OPTION
        );
        if (confirm == JOptionPane.YES_OPTION) {
            dbManager.clearHistory();
            textArea.setText("SQLite analysis history cleared.");
        }
    }
}