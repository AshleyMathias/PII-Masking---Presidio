import os

from dotenv import load_dotenv
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig

load_dotenv()

KEY = os.getenv("PRESIDIO_ENCRYPT_KEY")  # exactly 16 characters
if not KEY or len(KEY) != 16:
    raise EnvironmentError(
        "PRESIDIO_ENCRYPT_KEY must be set in your .env file and be exactly 16 characters."
    )

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
deanonymizer = DeanonymizeEngine()

text = "Hello, my name is John Doe. My email is john@example.com and my phone number is +91-9876543210."
results = analyzer.analyze(text=text, language="en")

# Anonymize with encryption (reversible)
anon_result = anonymizer.anonymize(
    text=text,
    analyzer_results=results,
    operators={"DEFAULT": OperatorConfig("encrypt", {"key": KEY})},
)
print("Encrypted text:")
print(anon_result.text)

restored = deanonymizer.deanonymize(
    text=anon_result.text,
    entities=anon_result.items,
    operators={"DEFAULT": OperatorConfig("decrypt", {"key": KEY})},
)
print("\nRestored text:")
print(restored.text)
