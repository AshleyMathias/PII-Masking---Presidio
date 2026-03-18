from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

text = "Hi, I'm John Doe. Reach me at john@example.com or +91-9876543210."
results = analyzer.analyze(text=text, language="en")

output = anonymizer.anonymize(
    text=text,
    analyzer_results=results,
    operators={
        "PERSON":        OperatorConfig("replace", {"new_value": "[NAME]"}),
        "EMAIL_ADDRESS": OperatorConfig("mask",    {"chars_to_mask": 6, "masking_char": "*", "from_end": False}),
        "PHONE_NUMBER":  OperatorConfig("redact",  {}),   # completely removes it
        "DEFAULT":       OperatorConfig("replace", {"new_value": "[REDACTED]"}),
    }
)
print(output.text)
# "Hi, I'm [NAME]. Reach me at jo*****@example.com or ."


