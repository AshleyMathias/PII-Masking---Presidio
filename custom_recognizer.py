from presidio_analyzer import PatternRecognizer, Pattern
from presidio_analyzer import AnalyzerEngine
analyzer = AnalyzerEngine()
recognizer = PatternRecognizer(
    supported_entity="AADHAAR_NUMBER",
    patterns=[
        Pattern(
            name="aadhaar_pattern",
            regex=r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b",
            score=0.85
        )
    ]
)

analyzer.registry.add_recognizer(recognizer)
results = analyzer.analyze(text="My Aadhaar is 2345 6789 0123", language="en")
for result in results:
    print(result)