from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

text = "Hi, I'm John Doe. Reach me at john@example.com or +91-9876543210."

# Step 1: detect
results = analyzer.analyze(text=text, language="en")
# results is a list of RecognizerResult objects
for r in results:
    print(r)
# RecognizerResult(type=PERSON, start=8, end=16, score=0.85)
# RecognizerResult(type=EMAIL_ADDRESS, start=29, end=45, score=1.0)
# RecognizerResult(type=PHONE_NUMBER, start=49, end=64, score=0.75)

# Step 2: anonymize
output = anonymizer.anonymize(text=text, analyzer_results=results)
print(output.text)
# "Hi, I'm <PERSON>. Reach me at <EMAIL_ADDRESS> or <PHONE_NUMBER>."