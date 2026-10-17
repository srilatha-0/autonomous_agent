import os
import csv
from dotenv import load_dotenv

from crewai import Knowledge
from crewai.knowledge.source.string_knowledge_source import StringKnowledgeSource


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

load_dotenv(
    os.path.join(BASE_DIR, ".env")
)


KNOWLEDGE_PATH = os.path.join(
    BASE_DIR,
    "rag_knowledge_base.csv"
)


def load_knowledge():

    documents = []

    with open(
        KNOWLEDGE_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            documents.append(
                f"""
Knowledge ID: {row['knowledge_id']}
Topic: {row['topic']}
Knowledge: {row['document_text']}
"""
            )

    return "\n\n".join(documents)


knowledge_content = load_knowledge()


knowledge_source = StringKnowledgeSource(
    content=knowledge_content
)


threat_knowledge = Knowledge(
    collection_name="rhym_threat_intelligence",
    sources=[knowledge_source],
    embedder={
        "provider": "ollama",
        "config": {
            "model_name": "nomic-embed-text:latest",
            "url": "http://localhost:11434/api/embeddings"
        }
    }
)


def initialize_rag():

    print("Initializing CrewAI RAG...")

    threat_knowledge.add_sources()

    print("RAG knowledge successfully indexed.")


def search_rag(
    query: str,
    results_limit: int = 5,
    score_threshold: float = 0.4
):

    results = threat_knowledge.query(
        query=[query],
        results_limit=results_limit,
        score_threshold=score_threshold
    )

    if not results:

        return "No relevant threat intelligence knowledge found."

    return "\n\n".join(
        str(result)
        for result in results
    )


if __name__ == "__main__":

    initialize_rag()

