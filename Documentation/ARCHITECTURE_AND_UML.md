# System Architecture & UML Class Diagram
**Project:** Automatic MITRE ATT&CK Technique Extraction from Threat Reports  
**Section:** SEC-G | **Registration ID:** AP25110070193

---

## 1. End-to-End Processing Architecture

```text
+-------------------------------------------------------------------+
|                     USER INTERFACE (Swing GUI)                    |
|  MainFrame.java: File Upload | Method Selector | Benchmark | DB   |
+---------------------------------+---------------------------------+
                                  | (SwingWorker Background Thread)
                                  v
+-------------------------------------------------------------------+
|                      INPUT PARSING LAYER                          |
|  ReportParser.java: Apache PDFBox (PDF) & Java NIO (TXT)          |
+---------------------------------+---------------------------------+
                                  | Extracted Report Text
                                  v
+-------------------------------------------------------------------+
|             POLYMORPHIC EXTRACTION ENGINE LAYER                   |
|                 <<interface>> ExtractorStrategy                   |
|                                                                   |
|  +-----------------------+  +-----------------+  +--------------+ |
|  |  TechniqueExtractor   |  | TfIdfExtractor  |  |  Semantic    | |
|  | (Rule/Keyword Engine) |  | (Cosine Sim.)   |  |  Extractor   | |
|  +-----------------------+  +-----------------+  +--------------+ |
+---------------------------------+---------------------------------+
                                  | List<Technique> (ID, Name, Tactic,
                                  |   Confidence Score, Evidence Span)
                 +----------------+----------------+
                 v                                 v
+---------------------------------+ +-------------------------------+
|    PERSISTENCE LAYER (JDBC)     | |    RESEARCH EVALUATION        |
|  DatabaseManager.java           | |  EvaluationBenchmark.java     |
|  SQLite (mitre_history.db)      | |  Precision, Recall, F1, MRR   |
+---------------------------------+ +-------------------------------+


+-------------------------------------------+       +-------------------------------------+
|                 MainFrame                 |------>|            ReportParser             |
+-------------------------------------------+       +-------------------------------------+
| - parser: ReportParser                    |       | + extractText(file: File): String   |
| - keywordStrategy: ExtractorStrategy      |       +-------------------------------------+
| - tfidfStrategy: ExtractorStrategy        |
| - semanticStrategy: ExtractorStrategy     |       +-------------------------------------+
| - dbManager: DatabaseManager              |------>|           DatabaseManager           |
| - benchmark: EvaluationBenchmark          |       +-------------------------------------+
+-------------------------------------------+       | - DB_URL: String                    |
| + extractReportInBackground(): void       |       | + saveAnalysis(...): void           |
| + runResearchBenchmark(): void            |       | + getRecentHistory(int): List       |
| + showDatabaseHistory(): void             |       | + clearHistory(): void              |
| + clearDatabaseHistory(): void            |       +-------------------------------------+
+-------------------------------------------+
          |                       |
          | uses                  | evaluates
          v                       v
+-----------------------------------+   +-----------------------------------+
|  <<interface>> ExtractorStrategy  |   |        EvaluationBenchmark        |
+-----------------------------------+   +-----------------------------------+
| + getStrategyName(): String       |   | + getAnnotatedTestSet(): List     |
| + extractTechniques(String): List |   | + evaluateStrategy(...): Result   |
+-----------------------------------+   +-----------------------------------+
                  ^
                  | implements
       +----------+----------+
       |          |          |
+------+----+ +---+------+ +-+---------------+
| Technique | |  TfIdf   | |    Semantic     |
| Extractor | |Extractor | |    Extractor    |
+-----------+ +----------+ +-----------------+
       |
       | instantiates
       v
+-------------------------------------------+
|                 Technique                 |
+-------------------------------------------+
| - id: String                              |
| - name: String                            |
| - tactic: String                          |
| - description: String                     |
| - evidence: String                        |
| - confidenceScore: double                 |
+-------------------------------------------+
| + getId(): String                         |
| + getName(): String                       |
| + getTactic(): String                     |
| + getDescription(): String                |
| + getEvidence(): String                   |
| + getConfidenceScore(): double            |
+-------------------------------------------+