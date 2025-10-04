"""
RAG Engine for AWS IAM Policy Generation

Main RAG engine that coordinates document processing, vector storage,
and context retrieval for AWS IAM policy generation.
"""

import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import re

from .document_processor import DocumentProcessor
from .vector_store_manager import VectorStoreManager


@dataclass
class RetrievalResult:
    """Result of context retrieval for a DSL query"""
    dsl_query: str
    retrieved_contexts: List[Dict[str, Any]]
    augmented_prompt: str
    retrieval_metadata: Dict[str, Any]


class RAGEngine:
    """
    Main RAG Engine for AWS IAM policy generation.

    Provides retrieval-augmented generation capabilities by:
    1. Processing AWS IAM documentation
    2. Storing chunks in vector database
    3. Retrieving relevant context for DSL queries
    4. Augmenting prompts for policy generation
    """

    def __init__(self,
                 vector_store_path: str = "./data/vector_store/",
                 embedding_model: str = "all-MiniLM-L6-v2"):
        """
        Initialize RAG Engine.

        Args:
            vector_store_path: Path for vector database storage
            embedding_model: Sentence transformer model for embeddings
        """
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.document_processor = DocumentProcessor()
        self.vector_store = VectorStoreManager(
            store_path=vector_store_path,
            embedding_model=embedding_model
        )

        # DSL parsing patterns for better context retrieval
        self.dsl_patterns = {
            'action': r'(?:ACTION:)?([a-z0-9\-]+:[A-Z][a-zA-Z0-9\*]+)',
            'service': r'([a-z0-9\-]+):',
            'resource': r'(?:ON|bucket:|instance:|role:)([a-zA-Z0-9\-\*\/]+)',
            'user': r'user:([a-zA-Z0-9\-\*]+)',
            'condition': r'WHERE\s+([a-zA-Z0-9\-\:]+)',
            'effect': r'^(ALLOW|DENY)'
        }

    def initialize_knowledge_base(self, aws_docs_path: str) -> bool:
        """
        Initialize the knowledge base by processing AWS IAM documentation.

        Args:
            aws_docs_path: Path to AWS IAM User Guide PDF

        Returns:
            True if successful, False otherwise
        """
        try:
            self.logger.info("Initializing RAG knowledge base...")

            # Check if documentation file exists
            if not Path(aws_docs_path).exists():
                self.logger.error(f"AWS documentation file not found: {aws_docs_path}")
                return False

            # Process the documentation
            self.logger.info("Processing AWS IAM documentation...")
            chunks = self.document_processor.process_document(aws_docs_path)

            if not chunks:
                self.logger.error("No chunks extracted from documentation")
                return False

            # Index chunks in vector store
            self.logger.info("Indexing chunks in vector store...")
            success = self.vector_store.index_documents(chunks)

            if success:
                # Save collection stats
                stats = self.vector_store.get_collection_stats()
                self.logger.info(f"Knowledge base initialized with {stats.get('total_chunks', 0)} chunks")

                # Save debug information
                stats_path = Path(self.vector_store.store_path) / "collection_stats.json"
                self.vector_store.save_collection_info(str(stats_path))

                return True
            else:
                self.logger.error("Failed to index documents in vector store")
                return False

        except Exception as e:
            self.logger.error(f"Error initializing knowledge base: {e}")
            return False

    def retrieve_context(self,
                        dsl_statement: str,
                        n_results: int = 5,
                        relevance_threshold: float = 0.3) -> RetrievalResult:
        """
        Retrieve relevant context for a DSL statement.

        Args:
            dsl_statement: The DSL statement to get context for
            n_results: Maximum number of context chunks to retrieve
            relevance_threshold: Minimum relevance score for results

        Returns:
            RetrievalResult with retrieved contexts and augmented prompt
        """
        try:
            self.logger.info(f"Retrieving context for DSL: {dsl_statement}")

            # Parse DSL to understand what to search for
            dsl_components = self._parse_dsl_statement(dsl_statement)

            # Determine chunk types to focus on
            chunk_types = self._determine_relevant_chunk_types(dsl_components)

            # Extract services from DSL
            services = self._extract_services_from_dsl(dsl_components)

            # Search for relevant contexts
            search_results = self.vector_store.search(
                query=dsl_statement,
                n_results=n_results * 2,  # Get more results to filter
                chunk_types=chunk_types,
                services=services
            )

            # Filter by relevance threshold
            relevant_results = [
                result for result in search_results
                if result['relevance_score'] >= relevance_threshold
            ][:n_results]

            # Create augmented prompt
            augmented_prompt = self._create_augmented_prompt(dsl_statement, relevant_results)

            # Prepare retrieval metadata
            retrieval_metadata = {
                'dsl_components': dsl_components,
                'chunk_types_searched': chunk_types,
                'services_searched': services,
                'total_results_found': len(search_results),
                'relevant_results_count': len(relevant_results),
                'average_relevance_score': sum(r['relevance_score'] for r in relevant_results) / len(relevant_results) if relevant_results else 0
            }

            return RetrievalResult(
                dsl_query=dsl_statement,
                retrieved_contexts=relevant_results,
                augmented_prompt=augmented_prompt,
                retrieval_metadata=retrieval_metadata
            )

        except Exception as e:
            self.logger.error(f"Error retrieving context: {e}")
            return RetrievalResult(
                dsl_query=dsl_statement,
                retrieved_contexts=[],
                augmented_prompt=self._create_fallback_prompt(dsl_statement),
                retrieval_metadata={'error': str(e)}
            )

    def _parse_dsl_statement(self, dsl_statement: str) -> Dict[str, List[str]]:
        """Parse DSL statement to extract components"""
        components = {}

        for component, pattern in self.dsl_patterns.items():
            matches = re.findall(pattern, dsl_statement, re.IGNORECASE)
            components[component] = matches

        return components

    def _determine_relevant_chunk_types(self, dsl_components: Dict[str, List[str]]) -> Optional[List[str]]:
        """Determine which chunk types are most relevant for the DSL"""
        relevant_types = []

        # If DSL has specific actions, prioritize action chunks
        if dsl_components.get('action'):
            relevant_types.append('action')

        # If DSL mentions resources, include resource chunks
        if dsl_components.get('resource'):
            relevant_types.append('resource')

        # If DSL has conditions, include condition chunks
        if dsl_components.get('condition'):
            relevant_types.append('condition')

        # If no specific components found, search all types
        return relevant_types if relevant_types else None

    def _extract_services_from_dsl(self, dsl_components: Dict[str, List[str]]) -> Optional[List[str]]:
        """Extract AWS service names from DSL components"""
        services = set()

        # Extract from actions (service:action format)
        for action in dsl_components.get('action', []):
            if ':' in action:
                service = action.split(':')[0]
                services.add(service)

        # Extract from service patterns
        for service in dsl_components.get('service', []):
            services.add(service)

        return list(services) if services else None

    def _create_augmented_prompt(self, dsl_statement: str, contexts: List[Dict[str, Any]]) -> str:
        """Create an augmented prompt with retrieved context"""

        base_prompt = f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {dsl_statement}"""

        if not contexts:
            return base_prompt + "\n\nGenerate a complete AWS IAM policy with Version and Statement fields. Use proper AWS ARN format for resources.\nOutput only valid JSON without markdown formatting:"

        # Add relevant context
        context_section = "\n\nRelevant AWS IAM Documentation Context:\n"

        for i, context in enumerate(contexts, 1):
            metadata = context['metadata']
            relevance = context['relevance_score']

            context_header = f"\n--- Context {i} (Relevance: {relevance:.2f}, Type: {metadata['chunk_type']}"
            if metadata.get('service') and metadata['service'] != 'unknown':
                context_header += f", Service: {metadata['service']}"
            context_header += ") ---"

            context_section += context_header
            context_section += f"\n{context['content'][:500]}...\n"  # Limit context length

        augmented_prompt = base_prompt + context_section

        augmented_prompt += """\n\nBased on the above AWS documentation context, generate a complete AWS IAM policy with Version and Statement fields.
Use proper AWS ARN format for resources and ensure the policy follows AWS IAM best practices.
Output only valid JSON without markdown formatting:"""

        return augmented_prompt

    def _create_fallback_prompt(self, dsl_statement: str) -> str:
        """Create a fallback prompt when no context is retrieved"""
        return f"""Convert this AWS IAM DSL statement to a valid AWS IAM policy JSON:

DSL: {dsl_statement}

Generate a complete AWS IAM policy with Version and Statement fields. Use proper AWS ARN format for resources.
Output only valid JSON without markdown formatting:"""

    def get_knowledge_base_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base"""
        return self.vector_store.get_collection_stats()

    def clear_knowledge_base(self) -> bool:
        """Clear the knowledge base"""
        return self.vector_store.clear_collection()


if __name__ == "__main__":
    # Test the RAG engine
    logging.basicConfig(level=logging.INFO)

    rag_engine = RAGEngine()

    # Test knowledge base initialization
    aws_docs_path = "/Users/brandonb/Documents/OMSCS/CS8903/NL2IAM/docs/iam-ug.pdf"

    if Path(aws_docs_path).exists():
        print("Initializing knowledge base...")
        success = rag_engine.initialize_knowledge_base(aws_docs_path)
        print(f"Knowledge base initialization: {'Success' if success else 'Failed'}")

        if success:
            # Test context retrieval
            test_dsl = "ALLOW user:alice ACTION:s3:GetObject ON bucket:public-bucket/*"
            print(f"\nTesting context retrieval for: {test_dsl}")

            result = rag_engine.retrieve_context(test_dsl)
            print(f"Retrieved {len(result.retrieved_contexts)} contexts")
            print(f"Average relevance: {result.retrieval_metadata.get('average_relevance_score', 0):.3f}")

            # Show knowledge base stats
            stats = rag_engine.get_knowledge_base_stats()
            print(f"\nKnowledge base stats:")
            print(f"Total chunks: {stats.get('total_chunks', 0)}")
            print(f"Chunk types: {stats.get('chunk_types', {})}")

    else:
        print(f"AWS documentation not found at: {aws_docs_path}")
        print("Please ensure the AWS IAM User Guide PDF is available.")