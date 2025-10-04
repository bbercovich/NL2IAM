"""
Vector Store Manager for AWS IAM Documentation

Manages the vector database for storing and retrieving AWS IAM documentation chunks.
Uses ChromaDB for vector storage and sentence-transformers for embeddings.
"""

import os
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
import json

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

from .document_processor import DocumentChunk


class VectorStoreManager:
    """
    Manages vector storage and retrieval for AWS IAM documentation chunks.
    """

    def __init__(self,
                 store_path: str = "./data/vector_store/",
                 embedding_model: str = "all-MiniLM-L6-v2",
                 collection_name: str = "aws_iam_docs"):
        """
        Initialize Vector Store Manager.

        Args:
            store_path: Path to store the vector database
            embedding_model: Sentence transformer model for embeddings
            collection_name: Name of the ChromaDB collection
        """
        self.store_path = Path(store_path)
        self.store_path.mkdir(parents=True, exist_ok=True)

        self.embedding_model_name = embedding_model
        self.collection_name = collection_name
        self.logger = logging.getLogger(__name__)

        # Initialize ChromaDB client
        self.client = chromadb.PersistentClient(
            path=str(self.store_path),
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )

        # Initialize embedding model
        self.logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)

        # Get or create collection
        self.collection = self._get_or_create_collection()

    def _get_or_create_collection(self):
        """Get existing collection or create a new one"""
        try:
            collection = self.client.get_collection(name=self.collection_name)
            self.logger.info(f"Using existing collection: {self.collection_name}")
            return collection
        except Exception:
            self.logger.info(f"Creating new collection: {self.collection_name}")
            return self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "AWS IAM documentation chunks"}
            )

    def index_documents(self, chunks: List[DocumentChunk], batch_size: int = 5000) -> bool:
        """
        Index document chunks in the vector store in batches.

        Args:
            chunks: List of DocumentChunk objects to index
            batch_size: Number of chunks to process in each batch

        Returns:
            True if successful, False otherwise
        """
        try:
            if not chunks:
                self.logger.warning("No chunks provided for indexing")
                return False

            self.logger.info(f"Indexing {len(chunks)} document chunks in batches of {batch_size}")

            # Process chunks in batches
            total_processed = 0
            for batch_start in range(0, len(chunks), batch_size):
                batch_end = min(batch_start + batch_size, len(chunks))
                batch_chunks = chunks[batch_start:batch_end]

                self.logger.info(f"Processing batch {batch_start//batch_size + 1}: chunks {batch_start+1} to {batch_end}")

                # Prepare data for ChromaDB
                documents = []
                metadatas = []
                ids = []

                for i, chunk in enumerate(batch_chunks):
                    # Create unique ID for each chunk
                    chunk_id = f"{chunk.chunk_type}_{chunk.page_number}_{batch_start + i}"

                    # Prepare document text for embedding
                    document_text = chunk.content

                    # Prepare metadata
                    metadata = {
                        "chunk_type": chunk.chunk_type,
                        "service": chunk.service or "unknown",
                        "action_name": chunk.action_name or "",
                        "resource_type": chunk.resource_type or "",
                        "condition_key": chunk.condition_key or "",
                        "page_number": chunk.page_number or 0,
                    }

                    # Add original metadata if present
                    if chunk.metadata:
                        metadata.update({f"original_{k}": str(v) for k, v in chunk.metadata.items()})

                    documents.append(document_text)
                    metadatas.append(metadata)
                    ids.append(chunk_id)

                # Generate embeddings for this batch
                self.logger.info(f"Generating embeddings for batch of {len(documents)} documents...")
                embeddings = self.embedding_model.encode(documents, convert_to_tensor=False)

                # Add to ChromaDB collection
                self.logger.info(f"Adding batch to vector store...")
                self.collection.add(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids,
                    embeddings=embeddings.tolist()
                )

                total_processed += len(batch_chunks)
                self.logger.info(f"Processed {total_processed}/{len(chunks)} chunks")

            self.logger.info(f"Successfully indexed all {len(chunks)} chunks")
            return True

        except Exception as e:
            self.logger.error(f"Error indexing documents: {e}")
            return False

    def search(self,
               query: str,
               n_results: int = 5,
               chunk_types: Optional[List[str]] = None,
               services: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Search for relevant document chunks based on query.

        Args:
            query: Search query (typically a DSL statement)
            n_results: Number of results to return
            chunk_types: Filter by chunk types (action, resource, condition)
            services: Filter by AWS services

        Returns:
            List of search results with content and metadata
        """
        try:
            # Generate query embedding
            query_embedding = self.embedding_model.encode([query], convert_to_tensor=False)

            # Build where clause for filtering
            where_clause = {}
            if chunk_types:
                where_clause["chunk_type"] = {"$in": chunk_types}
            if services:
                where_clause["service"] = {"$in": services}

            # Search in vector store
            results = self.collection.query(
                query_embeddings=query_embedding.tolist(),
                n_results=n_results,
                where=where_clause if where_clause else None,
                include=["documents", "metadatas", "distances"]
            )

            # Format results
            formatted_results = []
            if results["documents"] and results["documents"][0]:
                for i in range(len(results["documents"][0])):
                    result = {
                        "content": results["documents"][0][i],
                        "metadata": results["metadatas"][0][i],
                        "distance": results["distances"][0][i],
                        "relevance_score": 1.0 - results["distances"][0][i]  # Convert distance to relevance
                    }
                    formatted_results.append(result)

            self.logger.info(f"Found {len(formatted_results)} results for query: {query[:50]}...")
            return formatted_results

        except Exception as e:
            self.logger.error(f"Error searching vector store: {e}")
            return []

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the collection"""
        try:
            count = self.collection.count()

            # Get sample of metadata to understand content distribution
            sample_results = self.collection.get(limit=100, include=["metadatas"])

            chunk_types = {}
            services = {}

            if sample_results["metadatas"]:
                for metadata in sample_results["metadatas"]:
                    chunk_type = metadata.get("chunk_type", "unknown")
                    service = metadata.get("service", "unknown")

                    chunk_types[chunk_type] = chunk_types.get(chunk_type, 0) + 1
                    services[service] = services.get(service, 0) + 1

            return {
                "total_chunks": count,
                "chunk_types": chunk_types,
                "services": dict(list(services.items())[:10]),  # Top 10 services
                "collection_name": self.collection_name,
                "embedding_model": self.embedding_model_name
            }

        except Exception as e:
            self.logger.error(f"Error getting collection stats: {e}")
            return {}

    def clear_collection(self) -> bool:
        """Clear all documents from the collection"""
        try:
            # Delete the collection and recreate it
            self.client.delete_collection(name=self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "AWS IAM documentation chunks"}
            )
            self.logger.info("Collection cleared successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error clearing collection: {e}")
            return False

    def save_collection_info(self, output_path: str):
        """Save collection information to file"""
        try:
            stats = self.get_collection_stats()
            with open(output_path, 'w') as f:
                json.dump(stats, f, indent=2)
            self.logger.info(f"Collection info saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Error saving collection info: {e}")


if __name__ == "__main__":
    # Test the vector store manager
    logging.basicConfig(level=logging.INFO)

    # Initialize vector store
    vector_store = VectorStoreManager()

    # Test basic functionality
    stats = vector_store.get_collection_stats()
    print("Collection Stats:", json.dumps(stats, indent=2))

    # Test search (if collection has data)
    if stats.get("total_chunks", 0) > 0:
        test_query = "ALLOW user:alice READ bucket:public-bucket/*"
        results = vector_store.search(test_query, n_results=3)
        print(f"\nSearch results for '{test_query}':")
        for i, result in enumerate(results, 1):
            print(f"{i}. Score: {result['relevance_score']:.3f}")
            print(f"   Type: {result['metadata']['chunk_type']}")
            print(f"   Content: {result['content'][:100]}...")
            print()