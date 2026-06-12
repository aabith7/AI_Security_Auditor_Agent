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
    "You are a friendly Domo AppDB assistant. "
    "When a user greets you (e.g. 'hi', 'hello', 'hey'), respond with a short, warm welcome message only — "
    "do NOT list tools, capabilities, or examples unless the user specifically asks what you can do. "
    "RULES: "
    "1. A default collection is already configured — never ask the user for a collection_id. "
    "2. To find a document by a value, use find_documents_by_field. "
    "3. Before any delete, show the user what was found and ask them to confirm. "
    "Only delete after they explicitly say yes. "
    "4. Summarize results clearly and briefly."
)