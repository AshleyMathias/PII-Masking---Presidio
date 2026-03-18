import os
from dotenv import load_dotenv
from openai import OpenAI

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine
from presidio_anonymizer.entities import OperatorConfig

# Keep the LLM wrapper focused on high-signal PII types.
# This avoids encrypting benign entities (e.g., LOCATION) and reduces overlaps (e.g., URL inside EMAIL).
PII_ENTITY_ALLOWLIST = {
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "UK_NHS",
    "AADHAAR_NUMBER",
}

SCORE_THRESHOLD = 0.3


def _resolve_overlaps(results):
    """
    Presidio may return overlapping entities (e.g., URL spans inside an EMAIL span).
    For reversible transforms (encrypt/decrypt), we must avoid overlaps to keep mappings consistent.
    """

    if not results:
        return results

    # Prefer higher score, then longer span, then earlier start.
    ordered = sorted(results, key=lambda r: (-r.score, -(r.end - r.start), r.start))
    kept = []

    def overlaps(a, b) -> bool:
        return not (a.end <= b.start or b.end <= a.start)

    for r in ordered:
        if any(overlaps(r, k) for k in kept):
            continue
        kept.append(r)

    return sorted(kept, key=lambda r: (r.start, r.end))


# ---------------------------------------------------------------------------
# Load environment variables from .env
# ---------------------------------------------------------------------------
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o")
ENCRYPT_KEY    = os.getenv("PRESIDIO_ENCRYPT_KEY")  # exactly 16 characters

if not OPENAI_API_KEY:
    raise EnvironmentError("OPENAI_API_KEY is not set in your .env file.")
if not ENCRYPT_KEY or len(ENCRYPT_KEY) != 16:
    raise EnvironmentError(
        "PRESIDIO_ENCRYPT_KEY must be set in your .env file and be exactly 16 characters."
    )

# ---------------------------------------------------------------------------
# Initialize clients
# ---------------------------------------------------------------------------
openai_client = OpenAI(api_key=OPENAI_API_KEY)

analyzer     = AnalyzerEngine()
anonymizer   = AnonymizerEngine()
deanonymizer = DeanonymizeEngine()


# ---------------------------------------------------------------------------
# LLM caller — swap this out for any model/provider
# ---------------------------------------------------------------------------
def call_openai(text: str) -> str:
    """Send text to OpenAI and return the assistant's reply."""
    response = openai_client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a helpful assistant. "
                    "Some values in the user message are AES-encrypted PII tokens. "
                    "Treat them as opaque identifiers and echo them back verbatim "
                    "whenever you reference them."
                ),
            },
            {"role": "user", "content": text},
        ],
    )
    return response.choices[0].message.content


# ---------------------------------------------------------------------------
# Core privacy wrapper
# ---------------------------------------------------------------------------
def safe_llm_call(user_text: str) -> str:
    """
    1. Detect PII in user_text with Presidio Analyzer.
    2. Encrypt every detected span in place.
    3. Send the sanitized text to the LLM.
    4. Decrypt the LLM response back to real values.
    5. Return the final, restored response.
    """

    # --- Step 1: detect ---
    results = analyzer.analyze(
        text=user_text,
        language="en",
        score_threshold=SCORE_THRESHOLD,
    )

    # Keep only the entities we actually want to protect in this demo.
    results = [r for r in results if r.entity_type in PII_ENTITY_ALLOWLIST]
    results = _resolve_overlaps(results)

    if not results:
        # No PII found — call LLM directly, nothing to encrypt/decrypt
        print("[presidio] No PII detected. Passing text through directly.")
        return call_openai(user_text)

    print(f"[presidio] Detected {len(results)} PII entity/entities:")
    for r in results:
        print(f"          {r.entity_type} | pos {r.start}-{r.end} | score {r.score:.2f}")

    # --- Step 2: encrypt ---
    anon = anonymizer.anonymize(
        text=user_text,
        analyzer_results=results,
        operators={
            "DEFAULT": OperatorConfig("encrypt", {"key": ENCRYPT_KEY})
        },
    )
    print(f"[presidio] Anonymized text sent to LLM:\n          {anon.text}\n")

    # --- Step 3: call LLM ---
    llm_response = call_openai(anon.text)
    print(f"[presidio] Raw LLM response:\n          {llm_response}\n")

    # --- Step 4: decrypt ---
    try:
        deanon = deanonymizer.deanonymize(
            text=llm_response,
            entities=anon.items,
            operators={
                "DEFAULT": OperatorConfig("decrypt", {"key": ENCRYPT_KEY})
            },
        )
        return deanon.text
    except Exception as e:
        # The LLM may have paraphrased and dropped the encrypted tokens —
        # in that case return the raw response rather than crashing.
        print(f"[presidio] Deanonymization skipped (LLM did not echo tokens): {e}")
        return llm_response


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    test_inputs = [
        "My name is John Doe and my email is john.doe@example.com. Can you summarize my contact info?",
        "Please draft a short confirmation email to Sarah Connor at +91-9876543210.",
        "What is the capital of France?",  # no PII — should pass through directly
    ]

    for i, user_input in enumerate(test_inputs, 1):
        print(f"\n{'='*60}")
        print(f"[example {i}] User input:\n          {user_input}\n")
        result = safe_llm_call(user_input)
        print(f"[example {i}] Final response:\n          {result}")