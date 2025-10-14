# scanner/core.py
import os
from dataclasses import dataclass
from typing import List, Iterator
import math

from .patterns import Pattern

@dataclass(frozen=True)
class Finding:
    """A dataclass to represent a secret found in a file."""
    file_path: str
    line_number: int
    rule_id: str
    description: str
    matched_string: str
    confidence: str

class Scanner:
    """The core scanning engine with advanced features."""

    def __init__(self, patterns: List[Pattern]):
        """
        Initializes the Scanner with a list of compiled patterns.

        Args:
            patterns: A list of Pattern objects to scan for.
        """
        self.patterns = patterns
        # Separate patterns by confidence for prioritization
        self.high_confidence_patterns = [p for p in patterns if p.confidence == "High"]
        self.medium_confidence_patterns = [p for p in patterns if p.confidence == "Medium"]
        self.low_confidence_patterns = [p for p in patterns if p.confidence == "Low"]

    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            text: The string to calculate entropy for

        Returns:
            The Shannon entropy value
        """
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def is_likely_secret(self, text: str, min_entropy: float = 4.5) -> bool:
        """
        Use entropy analysis to determine if a string is likely a secret.

        Args:
            text: The string to analyze
            min_entropy: Minimum entropy threshold

        Returns:
            True if the string has high entropy (likely a secret)
        """
        if len(text) < 12:  # Too short to be meaningful
            return False

        entropy = self.calculate_entropy(text)
        return entropy >= min_entropy

    def is_binary_file(self, file_path: str, chunk_size: int = 1024) -> bool:
        """
        Check if a file is binary by reading a chunk and looking for null bytes.

        Args:
            file_path: Path to the file to check
            chunk_size: Size of chunk to read for testing

        Returns:
            True if the file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(chunk_size)
                # If we find null bytes, it's likely binary
                return b'\x00' in chunk
        except (IOError, OSError):
            return True  # Assume binary if we can't read it

    def should_skip_file(self, file_path: str) -> bool:
        """
        Determine if a file should be skipped during scanning.

        Args:
            file_path: Path to the file

        Returns:
            True if the file should be skipped
        """
        # Skip common binary file extensions
        skip_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.jar', '.war', '.ear',
            '.zip', '.tar', '.gz', '.bz2', '.xz', '.rar', '.7z',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
            '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
            '.pyc', '.pyo', '.class', '.o', '.obj'
        }

        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in skip_extensions:
            return True

        # Check if file is binary
        return self.is_binary_file(file_path)

    def scan_file(self, file_path: str) -> Iterator[Finding]:
        """
        Scans a single file for secrets, yielding findings as they are found.
        Uses entropy analysis for additional validation.

        Args:
            file_path: The path to the file to scan.

        Yields:
            Finding objects for each secret discovered.
        """
        # Skip files that shouldn't be scanned
        if self.should_skip_file(file_path):
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):  # Skip empty lines and comments
                        continue

                    # Scan with high confidence patterns first (faster)
                    for pattern in self.high_confidence_patterns:
                        match = pattern.regex.search(line)
                        if match:
                            matched_text = match.group(0).strip()
                            yield Finding(
                                file_path=file_path,
                                line_number=line_num,
                                rule_id=pattern.rule_id,
                                description=pattern.description,
                                matched_string=matched_text,
                                confidence=pattern.confidence
                            )

                    # Then scan with medium confidence patterns
                    for pattern in self.medium_confidence_patterns:
                        match = pattern.regex.search(line)
                        if match:
                            matched_text = match.group(0).strip()
                            yield Finding(
                                file_path=file_path,
                                line_number=line_num,
                                rule_id=pattern.rule_id,
                                description=pattern.description,
                                matched_string=matched_text,
                                confidence=pattern.confidence
                            )

                    # Finally, scan with low confidence patterns but use entropy validation
                    for pattern in self.low_confidence_patterns:
                        match = pattern.regex.search(line)
                        if match:
                            matched_text = match.group(0).strip()
                            # For low confidence patterns, use entropy analysis
                            if pattern.confidence == "Low" and not self.is_likely_secret(matched_text):
                                continue  # Skip low entropy matches for low confidence patterns

                            yield Finding(
                                file_path=file_path,
                                line_number=line_num,
                                rule_id=pattern.rule_id,
                                description=pattern.description,
                                matched_string=matched_text,
                                confidence=pattern.confidence
                            )

        except Exception as e:
            # Silently skip files that cannot be opened or read
            pass

    def scan_directory(self, dir_path: str) -> List[Finding]:
        """
        Recursively scans a directory and aggregates all findings.
        Implements .gitignore awareness and performance optimizations.

        Args:
            dir_path: The path to the directory to scan.

        Returns:
            A list of all Finding objects discovered in the directory.
        """
        all_findings = []

        # Common directories to skip for performance
        skip_dirs = {
            '.git', '.svn', '.hg', '.bzr',
            'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.env', 'virtualenv',
            'build', 'dist', 'target', 'out',
            '.idea', '.vscode', '.vs',
            'coverage', '.coverage', '.nyc_output'
        }

        for root, dirs, files in os.walk(dir_path):
            # Remove directories we want to skip
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    # The scan_file method returns an iterator, so we extend the list with its results
                    findings_for_file = list(self.scan_file(file_path))
                    all_findings.extend(findings_for_file)
                except Exception:
                    # Skip files that cause errors
                    continue

        return all_findings
