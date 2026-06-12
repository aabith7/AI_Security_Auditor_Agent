import os
from dotenv import load_dotenv

load_dotenv()

OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "")
DOMO_DEVELOPER_TOKEN = os.environ["DOMO_DEVELOPER_TOKEN"]
DOMO_COLLECTION_ID = os.environ["DOMO_COLLECTION_ID"]   # static default collection

MODEL = "minimax-m3:cloud"
MAX_TOKENS = 2048

DOMO_BASE_URL = "https://gwcteq-partner.domo.com/api/datastores"

SYSTEM_PROMPT = (
    "You are a Domo AppDB assistant. Use the provided tools to list, get, "
    "find, query, or delete documents. "
    "RULES: "
    "1. A default collection is already configured — you do NOT need to ask "
    "the user for a collection_id. Simply omit it when calling tools. "
    "2. When the user wants to find or delete a document by a value (like a name "
    "or userId), use find_documents_by_field or delete_documents_by_field. "
    "3. Before any delete, show the user what was found and ask them to confirm. "
    "Only delete after they say yes. "
    "4. Summarize JSON results clearly and briefly."
)