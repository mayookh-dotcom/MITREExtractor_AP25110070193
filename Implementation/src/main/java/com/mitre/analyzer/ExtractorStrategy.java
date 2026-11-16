package com.mitre.analyzer;

import java.util.List;

public interface ExtractorStrategy {
    String getStrategyName();
    List<Technique> extractTechniques(String text);
}