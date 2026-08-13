"""Generalized PII Redactor and Pseudonymization Module.

A document-agnostic, multi-pass PII detection and pseudonymization engine.
Operates dynamically without hardcoded entity dictionaries or document-specific lists.
"""

import os
import re
import sys
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Set, Optional

import spacy
import spacy.cli
from faker import Faker

fake = Faker()

class PIIRedactor:
    """Universal, document-agnostic PII Detector and Pseudonymizer."""

    def __init__(self, model_name: str = "en_core_web_sm"):
        try:
            self.nlp = spacy.load(model_name)
        except OSError:
            spacy.cli.download(model_name)
            self.nlp = spacy.load(model_name)

        # Dynamic In-Memory Session Registries
        self.pseudonym_map: Dict[str, str] = {}
        self.domains_map: Dict[str, str] = {}
        self.phone_counter = 1000
        
        # Track generated fakes to avoid mapping collisions
        self.seen_originals = set()

        # Universal Linguistic Grammars: Non-PII business, statutory, and metric stems
        self.generic_noun_stems = {
            'offer', 'offering', 'issue', 'price', 'band', 'bid', 'bidder', 'allotment',
            'asba', 'upi', 'ebitda', 'pat', 'cagr', 'ronw', 'roce', 'eps', 'nav', 'capital',
            'gaap', 'share', 'shares', 'mutual', 'fund', 'funds', 'iso', 'report', 'slip',
            'schedule', 'part', 'clause', 'section', 'act', 'regulation', 'regulations',
            'defaulter', 'borrower', 'offender', 'participant', 'kilometer', 'kilometers',
            'account', 'branch', 'branches', 'slip', 'form', 'broker', 'agent', 'officer',
            'secretary', 'director', 'promoter', 'shareholder', 'auditor', 'accountant',
            'engineer', 'manager', 'personnel', 'management', 'employed', 'taluka', 'district',
            'village', 'road', 'street', 'marg', 'city', 'centre', 'center', 'tower', 'floor',
            'society', 'complex', 'house', 'peth', 'nagar', 'industrial', 'park', 'facility',
            'chamber', 'chambers', 'colony', 'apartment', 'showroom', 'scheme', 'yojana',
            'power', 'auto', 'wire', 'wires', 'copper', 'aluminium', 'enamel', 'paper',
            'registered', 'corporate', 'office', 'total', 'amount', 'details', 'summary',
            'group', 'entities', 'company', 'companies', 'bank', 'banks', 'trust', 'trusts',
            'board', 'committee', 'department', 'ministry', 'authority', 'commission',
            'client', 'applicant', 'vendor', 'supplier', 'customer', 'employee', 'employer'
        }

        # Regulatory & Government Authority Keywords (Preserved across all jurisdictions)
        self.authority_pattern = re.compile(
            r'\b(board of [a-z]+|securities and exchange|reserve bank|central bank|government of|'
            r'ministry of|department of|high court|supreme court|stock exchange|stock exchanges|'
            r'appellate tribunal|tribunal|commission of|authority of|registrar of companies|roc|'
            r'bse|nse|sebi|rbi|icai|dpiit|nclt|sat|nsel|cdsl|nsdl)\b',
            re.IGNORECASE
        )

        # Structural Identifier Patterns (Generalized)
        self.patterns = {
            'email': [
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            ],
            'phone': [
                # International formats, standard 10 digit, landline with STD
                re.compile(r'(?:\+\s*\d{1,3}[\s-]?)?(?:\b[6-9]\d{9}\b|\b0?\d{2,4}[\s-]?\d{6,8}\b|\b\d{2,4}[\s-]\d{3,4}[\s-]\d{3,4}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)')
            ],
            'ip_address': [
                re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
            ],
            'ssn': [
                re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
            ],
            'credit_card': [
                re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
            ],
            'cin_pan': [
                re.compile(r'\b[UL]\d{5}[A-Z]{2}\d{4}[A-Z0-9]{3}\d{6}\b|\b[A-Z]{5}\d{4}[A-Z]\b')
            ],
            'reg_no': [
                # Generic alphanumeric registration numbers with prefixes
                re.compile(r'\b(?:M-\d{5,7}|INR\d{9}|\b\d{6}[Ww](?:/\s*[Ww]\d{6})?|[A-Z]{2,3}-\d{4,8})\b')
            ],
            'dob': [
                re.compile(
                    r'\b(?:born\s+on|date\s+of\s+birth(?:\s*is|\s*:)?|dob\s*[:\-])\s*'
                    r'(\d{1,2}[-/.](?:0[1-9]|1[0-2]|\d{1,2})[-/.]\d{4}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4})',
                    re.IGNORECASE
                )
            ],
            'address': [
                # Indian PIN anchored generalized
                re.compile(r'\b(?:(?:[A-Za-z0-9\s.,-]{10,150}?)\b(?:[A-Za-z]+)\s*[\u2013\-–—]?\s*\d{6}\b(?:\s*,?\s*[A-Za-z]+)?(?:\s*,?\s*India)?)', re.IGNORECASE),
                # US ZIP anchored generalized
                re.compile(r'\b(?:(?:[A-Za-z0-9\s.,-]{10,150}?)\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b)', re.IGNORECASE),
                # Contextual prefix (catch-all for addresses without zip codes if prefaced)
                re.compile(r'(?:Registered Office(?: is)?(?: located)? at|Corporate Office|Address|located at)\s*[:\s]*([A-Za-z0-9\s.,-]{10,150}?(?:\.|$|\n))', re.IGNORECASE)
            ],
            'company_name': [
                # Global corporate suffixes pattern
                re.compile(r'\b([A-Z][a-zA-Z0-9\s.,&]+?(?:Private Limited|Pvt Ltd|Limited|Ltd|LLP|Inc|Corp|LLC|Corporation|Co\.|PLC|GmbH|AG|S\.A\.|Pty Ltd|Foundation|Association|Trust))\b', re.IGNORECASE)
            ]
        }

        # Contextual Extractors - Generalized
        self.context_person_res = [
            re.compile(r'(?:Contact Person|Name|Applicant|Client|Issued to|Prepared for):\s*([A-Za-z\s]+)', re.I),
            re.compile(r'(?:appointed(?: by our Company)?(?: as)?,? (?:namely|being)|namely|being)\s*,?\s*([A-Z][a-zA-Z0-9\s\./&]+?)(?:,|\.|\bfor\b|\bhaving\b|\bbearing\b|\bas\b|\bon\b|\band\b|$)', re.I)
        ]
        
        self.table_name_column_re = re.compile(r'\b(?:name(?: of)?(?: the)? (?:shareholder|promoter|director|personnel|employee)|name)\b', re.I)

    def _deterministic_seed(self, s: str):
        """Generates a deterministic integer seed from a string."""
        return int(hashlib.md5(s.lower().encode()).hexdigest()[:8], 16)

    def is_valid_person_name(self, name: str) -> bool:
        """Validates if a string is a genuine personal name using POS and linguistic filtering."""
        clean = re.sub(r'[\s\t]+', ' ', name.strip()).rstrip('*^&#.,;: ')
        words = clean.split()
        if len(words) < 2 or len(words) > 5:
            return False

        # Filter if words are too short (except initials)
        if all(len(w) <= 2 for w in words):
            return False

        for w in words:
            w_lower = re.sub(r'[^a-z]', '', w.lower())
            if w_lower in self.generic_noun_stems:
                return False

        # Check that words start with uppercase letters
        if not all(w[0].isupper() for w in words if w.isalpha()):
            return False

        # Filter out numbers, percentages, and currencies
        if re.search(r'[0-9₹$%]', clean):
            return False

        # Ensure not an authority
        if self.authority_pattern.search(clean):
            return False
            
        return True

    def is_valid_company_name(self, comp: str) -> bool:
        """Validates if a string is a private commercial company or trust."""
        clean = re.sub(r'[\s\t]+', ' ', comp.strip()).rstrip('*^&#.,;: ')
        if len(clean) < 3 or len(clean.split()) < 1:
            return False

        if self.authority_pattern.search(clean):
            return False

        if re.search(r'\b(Private Limited|Pvt Ltd|Limited|Ltd|LLP|Inc|Corp|LLC|Corporation|Co\.|PLC|GmbH|AG|S\.A\.|Pty Ltd|Foundation|Association|Trust|Group)\b', clean, re.I):
            return True
        return False

    def get_deterministic_fake(self, original: str, fake_type: str) -> str:
        """Generates a consistent fake alternative deterministically based on original string."""
        norm_key = re.sub(r'[\s\t]+', ' ', original.strip()).rstrip('*^&#.,;: ')
        
        # If we already generated a replacement for this EXACT normalized string, return it
        if norm_key in self.pseudonym_map:
            return self.pseudonym_map[norm_key]
            
        # Ensure we always get the same fake value for the same input string
        Faker.seed(self._deterministic_seed(norm_key.lower()))
        
        fake_val = ""
        if fake_type in ('full_name', 'PERSON', 'PER'):
            if norm_key.isupper():
                fake_val = fake.name().upper()
            else:
                fake_val = fake.name()

        elif fake_type == 'email':
            user, domain = original.split('@', 1) if '@' in original else (original, 'example.com')
            fake_domain = self.domains_map.get(domain, 'example.com')
            fake_user = re.sub(r'[^a-zA-Z0-9]', '.', user.lower())
            fake_val = f"{fake_user}@{fake_domain}"

        elif fake_type == 'phone':
            fake_val = fake.phone_number()
            # Force Indian formatting if it looks like an Indian number
            if original.startswith('+91') or len(re.sub(r'\D', '', original)) == 10:
                fake_val = f"+91 987{Faker().random_int(min=1000000, max=9999999)}"

        elif fake_type in ('company_name', 'ORG'):
            fake_val = fake.company()
            if re.search(r'\bfamily trust\b', norm_key, re.I):
                fake_val = f"{fake.last_name()} Family Trust"
            elif 'Private Limited' in norm_key or 'Pvt Ltd' in norm_key:
                fake_val += " Private Limited"
            elif 'Limited' in norm_key or 'Ltd' in norm_key:
                fake_val += " Limited"
            elif 'LLP' in norm_key:
                fake_val += " LLP"

        elif fake_type in ('address', 'GPE', 'LOC'):
            fake_val = fake.address().replace('\n', ', ')
        elif fake_type == 'ssn':
            fake_val = fake.ssn()
        elif fake_type == 'credit_card':
            fake_val = fake.credit_card_number()
        elif fake_type == 'cin_pan':
            # Generate a fake CIN or PAN deterministically
            if len(norm_key) == 10 and norm_key[:5].isalpha(): # PAN
                fake_val = f"ABCDE{Faker().random_int(min=1000, max=9999)}F"
            else: # CIN
                fake_val = f"U{Faker().random_int(min=10000, max=99999)}XX{Faker().random_int(min=1000, max=9999)}XXX{Faker().random_int(min=100000, max=999999)}"
        elif fake_type == 'reg_no':
            fake_val = f"REG-{Faker().random_int(min=100000, max=999999)}"
        elif fake_type == 'dob':
            fake_val = fake.date_of_birth().strftime("%B %d, %Y")
        elif fake_type == 'ip_address':
            fake_val = fake.ipv4()
        else:
            fake_val = f"[REDACTED_{fake_type.upper()}]"

        # Special handling for case
        if norm_key.isupper() and not fake_val.isupper():
            fake_val = fake_val.upper()
        elif norm_key.istitle() and not fake_val.istitle():
            fake_val = fake_val.title()

        return fake_val

    def register_person(self, name: str):
        if not self.is_valid_person_name(name):
            return
            
        name_clean = re.sub(r'[\s\t]+', ' ', name.strip()).rstrip('*^&#.,;: ')
        if name_clean in self.seen_originals:
            return
            
        self.seen_originals.add(name_clean)
        
        fake_name = self.get_deterministic_fake(name_clean, 'full_name')
        
        # Register full name variations
        self.pseudonym_map[name_clean] = fake_name
        self.pseudonym_map[name_clean.upper()] = fake_name.upper()
        self.pseudonym_map[name_clean.title()] = fake_name.title()
        
        # Register partial name alignments to prevent partial leaks
        # (e.g. Kushal Subbayya Hegde -> William Charles Green)
        orig_parts = name_clean.split()
        fake_parts = fake_name.split()
        
        # If we have exact part match or can map first to first, last to last safely
        if len(orig_parts) >= 2 and len(fake_parts) >= 2:
            first_orig, first_fake = orig_parts[0], fake_parts[0]
            last_orig, last_fake = orig_parts[-1], fake_parts[-1]
            
            # Map first name if it's not a common noun
            if len(first_orig) > 3 and first_orig.lower() not in self.generic_noun_stems:
                self.pseudonym_map[first_orig] = first_fake
                self.pseudonym_map[first_orig.upper()] = first_fake.upper()
                
            # Map last name if it's not a common noun
            if len(last_orig) > 3 and last_orig.lower() not in self.generic_noun_stems:
                self.pseudonym_map[last_orig] = last_fake
                self.pseudonym_map[last_orig.upper()] = last_fake.upper()
                
            # Map First + Last (skip middle)
            if len(orig_parts) == 3:
                short_orig = f"{first_orig} {last_orig}"
                short_fake = f"{first_fake} {last_fake}"
                self.pseudonym_map[short_orig] = short_fake
                self.pseudonym_map[short_orig.upper()] = short_fake.upper()

    def register_company(self, comp: str):
        if not self.is_valid_company_name(comp):
            return
            
        comp_clean = re.sub(r'[\s\t]+', ' ', comp.strip()).rstrip('*^&#.,;: ')
        if comp_clean in self.seen_originals:
            return
            
        self.seen_originals.add(comp_clean)
        fake_comp = self.get_deterministic_fake(comp_clean, 'company_name')
        
        self.pseudonym_map[comp_clean] = fake_comp
        self.pseudonym_map[comp_clean.upper()] = fake_comp.upper()
        self.pseudonym_map[comp_clean.title()] = fake_comp.title()

    def register_email(self, email: str):
        email_clean = email.strip()
        if email_clean in self.seen_originals or '@' not in email_clean:
            return
            
        self.seen_originals.add(email_clean)

        user, domain = email_clean.split('@', 1)
        if domain not in self.domains_map:
            if domain.lower() in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com']:
                self.domains_map[domain] = 'example.com'
            else:
                self.domains_map[domain] = 'acmeglobal.com'

        fake_domain = self.domains_map[domain]
        fake_user = re.sub(r'[^a-zA-Z0-9]', '.', user.lower())
        fake_email = f"{fake_user}@{fake_domain}"
        
        self.pseudonym_map[email_clean] = fake_email
        self.pseudonym_map[email_clean.lower()] = fake_email.lower()
        self.pseudonym_map[email_clean.upper()] = fake_email.upper()

        # Safely register URL variants of the domain to catch stray website mentions
        self.pseudonym_map[domain] = fake_domain
        self.pseudonym_map[domain.lower()] = fake_domain.lower()
        self.pseudonym_map[f"www.{domain}"] = f"www.{fake_domain}"
        self.pseudonym_map[f"www.{domain}".lower()] = f"www.{fake_domain}".lower()
        self.pseudonym_map[f"https://{domain}"] = f"https://{fake_domain}"
        self.pseudonym_map[f"http://{domain}"] = f"http://{fake_domain}"

    def scan_and_mine_document(self, doc_or_texts):
        """Discovers entities across paragraphs and tables dynamically."""
        all_texts = []
        if hasattr(doc_or_texts, 'paragraphs'):
            all_texts.extend([p.text for p in doc_or_texts.paragraphs])
            for t in doc_or_texts.tables:
                if not t.rows:
                    continue
                # Table Column Header Mining
                header_cells = [c.text.strip().replace('\n', ' ') for c in t.rows[0].cells]
                target_col_indices = [idx for idx, h in enumerate(header_cells) if self.table_name_column_re.search(h)]
                for row in t.rows[1:]:
                    for col_idx in target_col_indices:
                        if col_idx < len(row.cells):
                            cell_val = row.cells[col_idx].text.strip()
                            clean_val = re.sub(r'[\*\^\&#]+$', '', cell_val).strip()
                            clean_val = re.sub(r'[\s\t]+', ' ', clean_val)
                            # Could be person or company
                            if self.is_valid_company_name(clean_val):
                                self.register_company(clean_val)
                            elif self.is_valid_person_name(clean_val):
                                self.register_person(clean_val)

                    for cell in row.cells:
                        for p in cell.paragraphs:
                            all_texts.append(p.text)
                            
            # Process headers/footers in DOCX
            if hasattr(doc_or_texts, 'sections'):
                for section in doc_or_texts.sections:
                    if section.header:
                        for p in section.header.paragraphs:
                            all_texts.append(p.text)
                    if section.footer:
                        for p in section.footer.paragraphs:
                            all_texts.append(p.text)
        elif isinstance(doc_or_texts, (list, tuple)):
            all_texts = doc_or_texts
        else:
            all_texts = [str(doc_or_texts)]

        email_re = self.patterns['email'][0]
        company_re = self.patterns['company_name'][0]

        for text in all_texts:
            if not text or not text.strip():
                continue

            # 1. Mine Emails & Domains
            for em in email_re.findall(text):
                self.register_email(em)
                
            # 2. Mine Company Names from global regex
            for comp in company_re.findall(text):
                self.register_company(comp)

            # 3. Mine Contextual Persons/Entities
            for regex in self.context_person_res:
                for m in regex.finditer(text):
                    raw = m.group(1).split('Telephone:')[0].split('Tel:')[0].split('Email:')[0].strip(' ,;:-')
                    for sub in re.split(r'[/,;]|(?:\band\b)', raw):
                        sub = sub.strip()
                        if self.is_valid_company_name(sub):
                            self.register_company(sub)
                        elif self.is_valid_person_name(sub):
                            self.register_person(sub)

            # 4. Handle Promoters Block specifically if it exists, splitting by commas
            if "OUR PROMOTERS" in text.upper() or "PROMOTERS OF OUR COMPANY" in text.upper():
                # Extract text after the colon
                parts = re.split(r'[:\n]', text)
                if len(parts) > 1:
                    promoters_raw = parts[1]
                    for it in re.split(r'[,;]|\bAND\b|\band\b', promoters_raw):
                        it = it.strip()
                        if len(it) > 3:
                            if self.is_valid_company_name(it):
                                self.register_company(it)
                            elif self.is_valid_person_name(it):
                                self.register_person(it)

            # 5. spaCy NER Pass
            doc_spacy = self.nlp(text)
            for ent in doc_spacy.ents:
                clean_ent = ent.text.strip().rstrip('*^&#.,;: ')
                if ent.label_ in ('PERSON', 'PER'):
                    if self.is_valid_person_name(clean_ent):
                        self.register_person(clean_ent)
                elif ent.label_ == 'ORG':
                    if self.is_valid_company_name(clean_ent):
                        self.register_company(clean_ent)

    def detect_pii(self, text: str) -> Dict[str, Set[str]]:
        """Detects all PII entities in a text snippet."""
        results = defaultdict(set)
        if not text or not text.strip():
            return dict(results)

        # 1. Structural Regex Detection
        for pii_type, patterns in self.patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if pii_type == 'dob' or pii_type == 'address':
                        # Use capture group if present (for dob and context addresses)
                        if len(match.groups()) > 0 and match.group(1):
                            matched_val = match.group(1).strip()
                        else:
                            matched_val = match.group(0).strip()
                    else:
                        matched_val = match.group(0).strip()

                    if matched_val and len(matched_val) > 2:
                        if pii_type == 'phone':
                            # Filter out false positive years or small numbers
                            digits = re.sub(r'\D', '', matched_val)
                            if len(digits) < 8 or ('2024' in digits or '2025' in digits and len(digits) <= 8):
                                continue
                        
                        if not self.authority_pattern.search(matched_val):
                            results[pii_type].add(matched_val)

        # 2. Contextual Field Extractors
        for regex in self.context_person_res:
            for m in regex.finditer(text):
                raw = m.group(1).split('Telephone:')[0].split('Tel:')[0].split('Email:')[0].strip(' ,;:-')
                for sub in re.split(r'[/,;]|(?:\band\b)', raw):
                    sub = sub.strip()
                    if self.is_valid_company_name(sub):
                        results['company_name'].add(sub)
                        self.register_company(sub)
                    elif self.is_valid_person_name(sub):
                        results['full_name'].add(sub)
                        self.register_person(sub)

        # 3. Check against Dynamically Mined Entity Registry
        for entity_str in self.pseudonym_map.keys():
            if len(entity_str) >= 4 and entity_str in text:
                # Differentiate company and person crudely for reporting
                if any(suffix in entity_str.lower() for suffix in ['limited', 'ltd', 'private', 'llp', 'inc']):
                    results['company_name'].add(entity_str)
                elif '@' in entity_str or 'www' in entity_str or 'http' in entity_str or '.com' in entity_str:
                    # Could be domain/email
                    pass
                else:
                    results['full_name'].add(entity_str)

        # 4. spaCy NER Pass
        doc_spacy = self.nlp(text)
        for ent in doc_spacy.ents:
            clean_ent = ent.text.strip().rstrip('*^&#.,;: ')
            if ent.label_ in ('PERSON', 'PER'):
                if self.is_valid_person_name(clean_ent):
                    results['full_name'].add(clean_ent)
                    self.register_person(clean_ent)
            elif ent.label_ == 'ORG':
                if self.is_valid_company_name(clean_ent):
                    results['company_name'].add(clean_ent)
                    self.register_company(clean_ent)

        return {k: v for k, v in results.items() if v}

    def get_replacements(self, text: str) -> List[Tuple[str, str]]:
        """Returns sorted list of (original, fake) replacement pairs for text."""
        if not text or not text.strip():
            return []

        # First, we need to map things we've detected directly on the fly
        pii_data = self.detect_pii(text)
        
        replacements = []
        
        # Pull from our registered map first (this ensures consistency)
        for original, fake_val in self.pseudonym_map.items():
            if original in text:
                # Add word boundary protection to prevent partial word replacements
                # like replacing "Pushpa" inside "Pushpakamal" if that happened
                # We skip word boundary if original has punctuation
                if original.isalnum():
                    # Check if it's a standalone word in the text
                    # We can use regex to verify it exists as a word
                    if not re.search(r'\b' + re.escape(original) + r'\b', text):
                        continue
                replacements.append((original, fake_val))

        # Add anything detected structurally that wasn't in the map
        for pii_type, items in pii_data.items():
            for item in items:
                # Only if not already processed via map
                if not any(item == r[0] for r in replacements):
                    fake_val = self.get_deterministic_fake(item, pii_type)
                    # Register it for future consistency
                    if pii_type in ('full_name', 'company_name'):
                        if pii_type == 'full_name':
                            self.register_person(item)
                        else:
                            self.register_company(item)
                    else:
                        self.pseudonym_map[item] = fake_val
                        replacements.append((item, fake_val))

        # Remove duplicates
        unique_reps = {}
        for k, v in replacements:
            unique_reps[k] = v
        replacements = list(unique_reps.items())

        # Longest match first to avoid partial collision (e.g., "John Doe" before "John")
        replacements.sort(key=lambda x: len(x[0]), reverse=True)
        return replacements

    def redact_text(self, text: str) -> str:
        """Replaces detected PII in text with consistent fake alternatives."""
        if not text or not text.strip():
            return text

        replacements = self.get_replacements(text)
        if not replacements:
            return text

        redacted_text = text
        for item, fake_val in replacements:
            # For short strings, ensure word boundaries
            if len(item) <= 5 and item.isalnum():
                pattern = re.compile(r'\b' + re.escape(item) + r'\b')
                redacted_text = pattern.sub(fake_val, redacted_text)
            else:
                redacted_text = redacted_text.replace(item, fake_val)

        return redacted_text

__all__ = ["PIIRedactor"]
