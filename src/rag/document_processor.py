"""
Document Processor for AWS IAM Documentation

Processes AWS IAM documentation PDF and extracts structured information
about Actions, Resources, and Conditions for vector indexing.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import PyPDF2
from io import BytesIO


@dataclass
class DocumentChunk:
    """Represents a chunk of AWS IAM documentation"""
    content: str
    chunk_type: str  # 'action', 'resource', 'condition'
    service: Optional[str] = None
    action_name: Optional[str] = None
    resource_type: Optional[str] = None
    condition_key: Optional[str] = None
    page_number: Optional[int] = None
    metadata: Optional[Dict] = None


class DocumentProcessor:
    """
    Processes AWS IAM documentation to extract structured chunks
    for vector indexing and retrieval.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Patterns for identifying different content types
        self.action_patterns = [
            r'([a-z0-9\-]+):([A-Z][a-zA-Z0-9\*]+)',  # service:Action format
            r'Action:\s*([a-z0-9\-]+):([A-Z][a-zA-Z0-9\*]+)',
            r'Actions?\s*(?:supported|available).*?([a-z0-9\-]+):([A-Z][a-zA-Z0-9\*]+)',
        ]

        self.resource_patterns = [
            r'Resource(?:s)?:\s*([a-zA-Z0-9\-\*\/\:]+)',
            r'ARN:\s*([a-zA-Z0-9\-\*\/\:]+)',
            r'arn:aws:([a-z0-9\-]+):',
        ]

        self.condition_patterns = [
            r'Condition(?:\s+key)?:\s*([a-zA-Z0-9\-\:\.]+)',
            r'([a-zA-Z0-9\-]+):([a-zA-Z0-9\-]+)',  # namespace:key format
            r'aws:([a-zA-Z0-9\-]+)',
        ]

    def process_document(self, pdf_path: str) -> List[DocumentChunk]:
        """
        Process AWS IAM documentation PDF and extract structured chunks.

        Args:
            pdf_path: Path to the AWS IAM User Guide PDF

        Returns:
            List of DocumentChunk objects containing structured content
        """
        self.logger.info(f"Processing document: {pdf_path}")

        try:
            chunks = []

            # Extract text from PDF
            text_content = self._extract_pdf_text(pdf_path)

            # Split into pages for better context
            pages = self._split_into_pages(text_content)

            for page_num, page_text in enumerate(pages, 1):
                # Extract different types of chunks from each page
                action_chunks = self._extract_action_chunks(page_text, page_num)
                resource_chunks = self._extract_resource_chunks(page_text, page_num)
                condition_chunks = self._extract_condition_chunks(page_text, page_num)

                chunks.extend(action_chunks)
                chunks.extend(resource_chunks)
                chunks.extend(condition_chunks)

            self.logger.info(f"Extracted {len(chunks)} chunks from document")
            return chunks

        except Exception as e:
            self.logger.error(f"Error processing document: {e}")
            raise

    def _extract_pdf_text(self, pdf_path: str) -> str:
        """Extract text content from PDF file"""
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text_content = []

                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        page_text = page.extract_text()
                        if page_text.strip():
                            text_content.append(f"===PAGE {page_num + 1}===\n{page_text}")
                    except Exception as e:
                        self.logger.warning(f"Could not extract text from page {page_num + 1}: {e}")
                        continue

                return "\n".join(text_content)

        except Exception as e:
            self.logger.error(f"Error reading PDF file: {e}")
            raise

    def _split_into_pages(self, text: str) -> List[str]:
        """Split text content into individual pages"""
        pages = []
        current_page = []

        for line in text.split('\n'):
            if line.startswith('===PAGE ') and current_page:
                pages.append('\n'.join(current_page))
                current_page = []
            else:
                current_page.append(line)

        if current_page:
            pages.append('\n'.join(current_page))

        return pages

    def _extract_action_chunks(self, text: str, page_num: int) -> List[DocumentChunk]:
        """Extract action-related chunks from text"""
        chunks = []

        # Look for action definitions and descriptions
        lines = text.split('\n')

        for i, line in enumerate(lines):
            for pattern in self.action_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)

                for match in matches:
                    service = match.group(1).lower() if match.lastindex >= 1 else None
                    action = match.group(2) if match.lastindex >= 2 else None

                    # Get surrounding context (3 lines before and after)
                    start_idx = max(0, i - 3)
                    end_idx = min(len(lines), i + 4)
                    context_lines = lines[start_idx:end_idx]
                    context = '\n'.join(context_lines)

                    chunk = DocumentChunk(
                        content=context,
                        chunk_type='action',
                        service=service,
                        action_name=action,
                        page_number=page_num,
                        metadata={
                            'line_number': i,
                            'match_pattern': pattern,
                            'full_match': match.group(0)
                        }
                    )
                    chunks.append(chunk)

        return chunks

    def _extract_resource_chunks(self, text: str, page_num: int) -> List[DocumentChunk]:
        """Extract resource-related chunks from text"""
        chunks = []
        lines = text.split('\n')

        for i, line in enumerate(lines):
            for pattern in self.resource_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)

                for match in matches:
                    resource_arn = match.group(1) if match.lastindex >= 1 else match.group(0)

                    # Extract service from ARN if possible
                    service = None
                    if ':' in resource_arn:
                        parts = resource_arn.split(':')
                        if len(parts) >= 3 and parts[0] == 'arn' and parts[1] == 'aws':
                            service = parts[2]

                    # Get surrounding context
                    start_idx = max(0, i - 3)
                    end_idx = min(len(lines), i + 4)
                    context_lines = lines[start_idx:end_idx]
                    context = '\n'.join(context_lines)

                    chunk = DocumentChunk(
                        content=context,
                        chunk_type='resource',
                        service=service,
                        resource_type=resource_arn,
                        page_number=page_num,
                        metadata={
                            'line_number': i,
                            'match_pattern': pattern,
                            'full_match': match.group(0)
                        }
                    )
                    chunks.append(chunk)

        return chunks

    def _extract_condition_chunks(self, text: str, page_num: int) -> List[DocumentChunk]:
        """Extract condition-related chunks from text"""
        chunks = []
        lines = text.split('\n')

        for i, line in enumerate(lines):
            for pattern in self.condition_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)

                for match in matches:
                    condition_key = match.group(1) if match.lastindex >= 1 else match.group(0)

                    # Get surrounding context
                    start_idx = max(0, i - 3)
                    end_idx = min(len(lines), i + 4)
                    context_lines = lines[start_idx:end_idx]
                    context = '\n'.join(context_lines)

                    chunk = DocumentChunk(
                        content=context,
                        chunk_type='condition',
                        condition_key=condition_key,
                        page_number=page_num,
                        metadata={
                            'line_number': i,
                            'match_pattern': pattern,
                            'full_match': match.group(0)
                        }
                    )
                    chunks.append(chunk)

        return chunks

    def save_chunks_to_file(self, chunks: List[DocumentChunk], output_path: str):
        """Save extracted chunks to a file for inspection"""
        import json

        chunks_data = []
        for chunk in chunks:
            chunk_dict = {
                'content': chunk.content,
                'chunk_type': chunk.chunk_type,
                'service': chunk.service,
                'action_name': chunk.action_name,
                'resource_type': chunk.resource_type,
                'condition_key': chunk.condition_key,
                'page_number': chunk.page_number,
                'metadata': chunk.metadata
            }
            chunks_data.append(chunk_dict)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(chunks_data, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Saved {len(chunks)} chunks to {output_path}")


if __name__ == "__main__":
    # Test the document processor
    logging.basicConfig(level=logging.INFO)

    processor = DocumentProcessor()

    # Process the AWS IAM documentation
    pdf_path = "/Users/brandonb/Documents/OMSCS/CS8903/NL2IAM/docs/iam-ug.pdf"
    chunks = processor.process_document(pdf_path)

    # Save chunks for inspection
    output_path = "/Users/brandonb/Documents/OMSCS/CS8903/NL2IAM/data/extracted_chunks.json"
    processor.save_chunks_to_file(chunks, output_path)

    print(f"Processed {len(chunks)} chunks")
    print(f"Action chunks: {len([c for c in chunks if c.chunk_type == 'action'])}")
    print(f"Resource chunks: {len([c for c in chunks if c.chunk_type == 'resource'])}")
    print(f"Condition chunks: {len([c for c in chunks if c.chunk_type == 'condition'])}")