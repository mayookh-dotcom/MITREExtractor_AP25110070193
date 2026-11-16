# Automatic MITRE ATT&CK Technique Extraction from Threat Reports

Section: SEC-G | Registration ID: AP25110070193

## Folder Structure
- Dataset/ : Annotated CTI threat report test passages and sample input files
- Implementation/ : Maven Java 21 project (Swing GUI, Apache PDFBox, SQLite JDBC, 3 Extraction Engines, RQ1 Evaluation Benchmark)
- Documentation/ : System Architecture and UML Class Diagrams
- Report/ : 15-20 Page Academic Project Report
- PPT/ : Final Review Presentation Slides (divided across all 5 members)

## How to Run
1. cd Implementation
2. mvn clean compile exec:java -Dexec.mainClass="com.mitre.Main"
