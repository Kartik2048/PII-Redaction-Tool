"""
Core PII Redaction Engine (redactor.py)

This module provides a production-ready, hybrid PII redaction engine combining
Presidio Analyzer, spaCy NER, custom deterministic regex recognizers, Luhn algorithm validation,
an execution-scoped/thread-safe Faker PseudonymMapper, and docx layout-preserving redactor.
"""

import io
import re
import threading
from dataclasses import dataclass
from typing import Union, BinaryIO, List, Dict, Tuple, Any, Optional

from faker import Faker
import docx
from docx.text.paragraph import Paragraph

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider


# ---------------------------------------------------------------------------
# Luhn Algorithm Checksum
# ---------------------------------------------------------------------------
def is_valid_luhn(card_number_str: str) -> bool:
    """Validate numeric string against the Luhn algorithm checksum."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Custom Presidio Pattern Recognizers
# ---------------------------------------------------------------------------
class CustomEmailRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="email_regex",
                regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                score=1.0,
            )
        ]
        super().__init__(
            supported_entity="EMAIL",
            patterns=patterns,
            name="CustomEmailRecognizer",
        )


class CustomPhoneRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="phone_regex",
                regex=r"\+?\s*91[\s-]?\d{2,5}[\s-]?\d{6,8}|\+?\d{1,4}?[\s-]?\(?\d{1,4}?\)?[\s-]?\d{1,4}[\s-]?\d{1,9}",
                score=0.95,
            )
        ]
        super().__init__(
            supported_entity="PHONE",
            patterns=patterns,
            name="CustomPhoneRecognizer",
        )


class CustomIPAddressRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="ip_address_regex",
                regex=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                score=1.0,
            )
        ]
        super().__init__(
            supported_entity="IP_ADDRESS",
            patterns=patterns,
            name="CustomIPAddressRecognizer",
        )


class CustomCreditCardRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="credit_card_regex",
                regex=r"\b(?:\d[ -]*?){13,16}\b",
                score=1.0,
            )
        ]
        super().__init__(
            supported_entity="CREDIT_CARD",
            patterns=patterns,
            name="CustomCreditCardRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate candidate credit card match using Luhn checksum."""
        return is_valid_luhn(pattern_text)


class CustomGovtIDRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="us_ssn",
                regex=r"\b\d{3}-\d{2}-\d{4}\b",
                score=1.0,
            ),
            Pattern(
                name="indian_pan",
                regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
                score=1.0,
            ),
            Pattern(
                name="indian_aadhaar",
                regex=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                score=0.95,
            ),
            Pattern(
                name="corporate_identity_number_cin",
                regex=r"\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}\b",
                score=1.0,
            ),
        ]
        super().__init__(
            supported_entity="SSN_GOVT_ID",
            patterns=patterns,
            name="CustomGovtIDRecognizer",
        )


class CustomDateOfBirthRecognizer(PatternRecognizer):
    def __init__(self, **kwargs):
        patterns = [
            Pattern(
                name="dob_numeric",
                regex=r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
                score=0.95,
            ),
            Pattern(
                name="dob_textual",
                regex=r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4}\b",
                score=0.95,
            ),
        ]
        super().__init__(
            supported_entity="DATE_OF_BIRTH",
            patterns=patterns,
            name="CustomDateOfBirthRecognizer",
        )


# ---------------------------------------------------------------------------
# Persistent Thread-Safe Pseudonym Mapper
# ---------------------------------------------------------------------------
class PseudonymMapper:
    """
    Thread-safe, execution-scoped persistent pseudonym dictionary.
    Ensures consistent fake value substitution across a document lifecycle.
    """

    def __init__(self, locale: str = "en_US", seed: Optional[int] = None):
        self._faker = Faker(locale)
        if seed is not None:
            self._faker.seed_instance(seed)
        self._lock = threading.Lock()
        self._mapping: Dict[Tuple[str, str], str] = {}
        self._used_values: set = set()

    def get_pseudonym(self, original_text: str, entity_type: str) -> str:
        clean_text = original_text.strip()
        key = (entity_type, clean_text)
        with self._lock:
            if key in self._mapping:
                return self._mapping[key]

            fake_val = self._generate_fake(clean_text, entity_type)
            attempts = 0
            while fake_val in self._used_values and attempts < 50:
                fake_val = self._generate_fake(clean_text, entity_type)
                attempts += 1

            self._used_values.add(fake_val)
            self._mapping[key] = fake_val
            return fake_val

    def _generate_fake(self, original_text: str, entity_type: str) -> str:
        et = entity_type.upper()
        if et in ("PERSON", "FULL_NAMES"):
            return self._faker.name()
        elif et in ("EMAIL", "EMAIL_ADDRESS"):
            return self._faker.email()
        elif et in ("PHONE", "PHONE_NUMBER"):
            return self._faker.phone_number()
        elif et in ("IP_ADDRESS", "IP"):
            return self._faker.ipv4()
        elif et == "CREDIT_CARD":
            return self._faker.credit_card_number()
        elif et == "SSN_GOVT_ID":
            return self._faker.bothify(text="???-##-####").upper()
        elif et in ("DATE_OF_BIRTH", "DATE_TIME"):
            return self._faker.date()
        elif et in ("ORGANIZATION", "COMPANY_NAMES"):
            return self._faker.company()
        elif et in ("LOCATION", "ADDRESSES"):
            return f"{self._faker.city()}, {self._faker.state()}"
        else:
            return f"[REDACTED_{et}]"

    def get_all_mappings(self) -> Dict[str, str]:
        with self._lock:
            return {orig: fake for (_, orig), fake in self._mapping.items()}


# ---------------------------------------------------------------------------
# Core PIIRedactor Engine
# ---------------------------------------------------------------------------
@dataclass
class DetectedEntity:
    entity_type: str
    original_text: str
    pseudonym: str
    confidence_score: float
    start: int
    end: int


class PIIRedactor:
    """
    Core PII Engine combining Presidio Analyzer, spaCy NER, custom pattern recognizers,
    contextual score boosting, and python-docx layout preservation.
    """

    CONTEXT_TRIGGERS = [
        "Promoter:",
        "Promoter",
        "Compliance Officer",
        "Registered Office",
        "Pvt Ltd",
        "Limited",
        "LLP",
        "Director:",
        "Authorized Signatory",
        "CIN:",
    ]

    DETERMINISTIC_ENTITIES = {
        "EMAIL",
        "PHONE",
        "IP_ADDRESS",
        "CREDIT_CARD",
        "SSN_GOVT_ID",
        "DATE_OF_BIRTH",
    }

    def __init__(self, spacy_model: str = "en_core_web_sm"):
        # Setup spaCy NLP provider for Presidio
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": spacy_model}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()

        # Initialize Recognizer Registry
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)

        # Register custom recognizers
        registry.add_recognizer(CustomEmailRecognizer())
        registry.add_recognizer(CustomPhoneRecognizer())
        registry.add_recognizer(CustomIPAddressRecognizer())
        registry.add_recognizer(CustomCreditCardRecognizer())
        registry.add_recognizer(CustomGovtIDRecognizer())
        registry.add_recognizer(CustomDateOfBirthRecognizer())

        self.analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=["en"]
        )

        # Map Presidio standard entities to requirement names
        self.entity_type_map = {
            "PERSON": "FULL_NAMES",
            "ORGANIZATION": "COMPANY_NAMES",
            "LOCATION": "ADDRESSES",
            "EMAIL_ADDRESS": "EMAIL",
            "PHONE_NUMBER": "PHONE",
        }

    def analyze_text(self, text: str) -> List[RecognizerResult]:
        """Analyze text with Presidio and apply contextual score boosting."""
        if not text or not text.strip():
            return []

        # Analyze with Presidio
        results = self.analyzer.analyze(
            text=text,
            language="en",
            score_threshold=0.35,
        )

        # Contextual Score Boosting for Legal/Corporate Triggers
        boosted_results: List[RecognizerResult] = []
        has_trigger = any(trigger in text for trigger in self.CONTEXT_TRIGGERS)

        for res in results:
            score = res.score
            if has_trigger and res.entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
                # Boost confidence score for NER entities in corporate/legal context
                score = min(1.0, score + 0.35)
                res.score = score
            boosted_results.append(res)

        return boosted_results

    def _resolve_overlapping_entities(
        self, results: List[RecognizerResult]
    ) -> List[RecognizerResult]:
        """
        Resolve overlapping entity intervals. Deterministic regex rules take precedence
        over generic spaCy NER tags when spans overlap.
        """
        if not results:
            return []

        # Helper to determine priority
        def priority_tuple(r: RecognizerResult):
            is_deterministic = r.entity_type in self.DETERMINISTIC_ENTITIES
            span_len = r.end - r.start
            return (r.start, 1 if is_deterministic else 0, r.score, span_len)

        # Sort by start position ascending, deterministic preference, then score
        sorted_results = sorted(results, key=priority_tuple)

        resolved: List[RecognizerResult] = []
        for res in sorted_results:
            if not resolved:
                resolved.append(res)
                continue

            last = resolved[-1]
            # Check overlap: max(start) < min(end)
            if max(res.start, last.start) < min(res.end, last.end):
                last_is_det = last.entity_type in self.DETERMINISTIC_ENTITIES
                res_is_det = res.entity_type in self.DETERMINISTIC_ENTITIES

                if res_is_det and not last_is_det:
                    resolved[-1] = res
                elif last_is_det and not res_is_det:
                    pass
                else:
                    if res.score > last.score:
                        resolved[-1] = res
            else:
                resolved.append(res)

        return resolved

    def redact_paragraph(
        self, paragraph: Paragraph, pseudonym_mapper: PseudonymMapper
    ) -> List[DetectedEntity]:
        """
        Redact PII in a docx Paragraph while preserving run-level formatting
        (bold, italics, font size, font family, colors).
        """
        full_text = paragraph.text
        if not full_text or not full_text.strip():
            return []

        analysis_results = self.analyze_text(full_text)
        resolved_results = self._resolve_overlapping_entities(analysis_results)

        if not resolved_results:
            return []

        detected_entities: List[DetectedEntity] = []
        replacements: List[Tuple[int, int, str]] = []

        for res in resolved_results:
            orig_text = full_text[res.start:res.end]
            mapped_type = self.entity_type_map.get(res.entity_type, res.entity_type)
            fake_val = pseudonym_mapper.get_pseudonym(orig_text, mapped_type)

            detected_entities.append(
                DetectedEntity(
                    entity_type=mapped_type,
                    original_text=orig_text,
                    pseudonym=fake_val,
                    confidence_score=res.score,
                    start=res.start,
                    end=res.end,
                )
            )
            replacements.append((res.start, res.end, fake_val))

        # Perform run-level substitution from right to left (end to start)
        self._apply_run_replacements(paragraph, replacements)
        return detected_entities

    def _apply_run_replacements(
        self, paragraph: Paragraph, replacements: List[Tuple[int, int, str]]
    ) -> None:
        """
        Safely replace text intervals in a paragraph across runs.
        Processes replacements in reverse order of start index to maintain valid offsets.
        """
        if not paragraph.runs or not replacements:
            return

        # Sort replacements by start index descending
        sorted_replacements = sorted(replacements, key=lambda r: r[0], reverse=True)

        for start, end, replacement in sorted_replacements:
            # Build current run bounds
            run_bounds: List[Tuple[int, int]] = []
            curr_pos = 0
            for run in paragraph.runs:
                run_len = len(run.text)
                run_bounds.append((curr_pos, curr_pos + run_len))
                curr_pos += run_len

            # Find target runs intersecting [start, end)
            target_run_indices = [
                i
                for i, (r_start, r_end) in enumerate(run_bounds)
                if max(start, r_start) < min(end, r_end)
            ]

            if not target_run_indices:
                continue

            first_idx = target_run_indices[0]
            last_idx = target_run_indices[-1]

            first_run = paragraph.runs[first_idx]
            first_r_start, _ = run_bounds[first_idx]
            prefix = first_run.text[: start - first_r_start]

            if first_idx == last_idx:
                suffix = first_run.text[end - first_r_start :]
                first_run.text = prefix + replacement + suffix
            else:
                last_run = paragraph.runs[last_idx]
                last_r_start, _ = run_bounds[last_idx]
                suffix = last_run.text[end - last_r_start :]

                first_run.text = prefix + replacement
                last_run.text = suffix

                # Clear text in intermediate runs
                for mid_idx in range(first_idx + 1, last_idx):
                    paragraph.runs[mid_idx].text = ""

    def process_table(
        self, table: Any, pseudonym_mapper: PseudonymMapper
    ) -> List[DetectedEntity]:
        """Safely iterate through docx table cells and cell paragraphs."""
        entities: List[DetectedEntity] = []
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    entities.extend(self.redact_paragraph(p, pseudonym_mapper))
                # Recursively process nested tables if any
                for nested_table in cell.tables:
                    entities.extend(self.process_table(nested_table, pseudonym_mapper))
        return entities

    def redact_docx(
        self,
        doc_input: Union[str, BinaryIO, bytes],
        pseudonym_mapper: Optional[PseudonymMapper] = None,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Redact a .docx document provided as a file path, stream, or bytes.

        Returns:
            Tuple[bytes, Dict[str, Any]]: Redacted document bytes and JSON metadata summary.
        """
        if pseudonym_mapper is None:
            pseudonym_mapper = PseudonymMapper()

        if isinstance(doc_input, bytes):
            doc_stream = io.BytesIO(doc_input)
        elif isinstance(doc_input, str):
            with open(doc_input, "rb") as f:
                doc_stream = io.BytesIO(f.read())
        else:
            doc_stream = doc_input

        doc = docx.Document(doc_stream)
        all_detected_entities: List[DetectedEntity] = []

        # 1. Main Document Paragraphs
        for p in doc.paragraphs:
            all_detected_entities.extend(self.redact_paragraph(p, pseudonym_mapper))

        # 2. Main Document Tables
        for table in doc.tables:
            all_detected_entities.extend(self.process_table(table, pseudonym_mapper))

        # 3. Document Sections (Headers and Footers)
        for section in doc.sections:
            for header in (
                section.header,
                getattr(section, "first_page_header", None),
                getattr(section, "even_page_header", None),
            ):
                if header is not None and not getattr(header, "is_linked_to_previous", False):
                    for hp in header.paragraphs:
                        all_detected_entities.extend(
                            self.redact_paragraph(hp, pseudonym_mapper)
                        )
                    for ht in header.tables:
                        all_detected_entities.extend(
                            self.process_table(ht, pseudonym_mapper)
                        )

            for footer in (
                section.footer,
                getattr(section, "first_page_footer", None),
                getattr(section, "even_page_footer", None),
            ):
                if footer is not None and not getattr(footer, "is_linked_to_previous", False):
                    for fp in footer.paragraphs:
                        all_detected_entities.extend(
                            self.redact_paragraph(fp, pseudonym_mapper)
                        )
                    for ft in footer.tables:
                        all_detected_entities.extend(
                            self.process_table(ft, pseudonym_mapper)
                        )

        # Save redacted document to BytesIO stream
        out_stream = io.BytesIO()
        doc.save(out_stream)
        redacted_bytes = out_stream.getvalue()

        # Build Metadata Summary
        entity_counts: Dict[str, int] = {}
        entity_occurrences: Dict[Tuple[str, str, str], int] = {}
        entity_scores: Dict[Tuple[str, str], float] = {}

        for ent in all_detected_entities:
            entity_counts[ent.entity_type] = entity_counts.get(ent.entity_type, 0) + 1
            key = (ent.entity_type, ent.original_text, ent.pseudonym)
            entity_occurrences[key] = entity_occurrences.get(key, 0) + 1
            entity_scores[(ent.entity_type, ent.original_text)] = ent.confidence_score

        detected_entities_list = [
            {
                "entity_type": ent_type,
                "original_text": orig,
                "pseudonym": fake,
                "confidence_score": entity_scores.get((ent_type, orig), 1.0),
                "count": count,
            }
            for (ent_type, orig, fake), count in entity_occurrences.items()
        ]

        metadata = {
            "total_entities_found": len(all_detected_entities),
            "entity_counts": entity_counts,
            "pseudonym_mappings": pseudonym_mapper.get_all_mappings(),
            "detected_entities": detected_entities_list,
        }

        return redacted_bytes, metadata


# ---------------------------------------------------------------------------
# Module Entrypoint / Helper
# ---------------------------------------------------------------------------
def redact_document(
    doc_input: Union[str, BinaryIO, bytes],
    spacy_model: str = "en_core_web_sm",
    pseudonym_mapper: Optional[PseudonymMapper] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Convenience function to redact a docx document and return redacted bytes + metadata summary.
    """
    engine = PIIRedactor(spacy_model=spacy_model)
    return engine.redact_docx(doc_input, pseudonym_mapper=pseudonym_mapper)
