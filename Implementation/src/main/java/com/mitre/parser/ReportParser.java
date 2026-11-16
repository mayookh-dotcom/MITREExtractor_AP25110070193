
package com.mitre.parser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

public class ReportParser {

    public String extractText(File file) throws IOException {

        String fileName = file.getName().toLowerCase();

        if (fileName.endsWith(".pdf")) {

            try (PDDocument document = Loader.loadPDF(file)) {

                PDFTextStripper stripper = new PDFTextStripper();

                return stripper.getText(document);
            }

        } else if (fileName.endsWith(".txt")) {

            return Files.readString(
                file.toPath(),
                StandardCharsets.UTF_8
            );

        } else {

            throw new IOException("Unsupported file format.");
        }
    }
}
