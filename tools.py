"""Tool schemas + registry. collection_id is optional — defaults to DOMO_COLLECTION_ID from .env"""
from domo_client import DomoAppDBClient
from config import DOMO_COLLECTION_ID

client = DomoAppDBClient()

_COLLECTION_PARAM = {
    "type": "string",
    "description": "Optional. Omit to use the default configured collection.",
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "list_documents",
            "description": "List all documents in the collection, with their IDs and content.",
            "parameters": {
                "type": "object",
                "properties": {"collection_id": _COLLECTION_PARAM},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_document",
            "description": "Retrieve a single document by its ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "collection_id": _COLLECTION_PARAM,
                    "document_id": {"type": "string", "description": "The document ID to retrieve"},
                },
                "required": ["document_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_documents_by_field",
            "description": (
                "Find documents where a field inside the document content matches a value. "
                "Use whenever the user wants to find/see/search a document by a value, "
                "e.g. 'show the document where name is santhosh'. "
                "Pass the plain field name only — 'content.' prefix is added automatically. "
                "Handles case-insensitive and partial matches. "
                "Returns matching documents WITH their document_id."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "collection_id": _COLLECTION_PARAM,
                    "field": {"type": "string", "description": "Field name, e.g. 'name' or 'userId'"},
                    "value": {"type": "string", "description": "The value to search for"},
                },
                "required": ["field", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_documents",
            "description": (
                "Advanced: raw MongoDB-style query, e.g. {\"content.age\": {\"$gt\": 25}}. "
                "For simple value lookups use find_documents_by_field instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "collection_id": _COLLECTION_PARAM,
                    "query": {"type": "object", "description": "MongoDB-style query with 'content.' prefixed fields"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_documents_by_field",
            "description": (
                "Delete document(s) where a content field matches a value. "
                "Irreversible — only call AFTER the user has confirmed. "
                "Plain field name, no 'content.' prefix."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "collection_id": _COLLECTION_PARAM,
                    "field": {"type": "string", "description": "Field name inside document content"},
                    "value": {"type": "string", "description": "The value to match"},
                },
                "required": ["field", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_document",
            "description": "Delete one document by its exact ID. Irreversible — only after user confirms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "collection_id": _COLLECTION_PARAM,
                    "document_id": {"type": "string", "description": "The document ID to delete"},
                },
                "required": ["document_id"],
            },
        },
    },
]

TOOL_REGISTRY = {
    "list_documents": client.list_documents,
    "get_document": client.get_document,
    "find_documents_by_field": client.find_documents_by_field,
    "query_documents": client.query_documents,
    "delete_documents_by_field": client.delete_documents_by_field,
    "delete_document": client.delete_document,
}


def execute_tool(name: str, args: dict) -> str:
    fn = TOOL_REGISTRY.get(name)
    if fn is None:
        return f"ERROR: unknown tool '{name}'"

    if not args.get("collection_id"):
        args["collection_id"] = DOMO_COLLECTION_ID
    try:
        result = fn(**args)
    except Exception as e:
        result = f"ERROR: {e}"
    print(f"   tool result: {result[:300]}")   # debug — see raw API response
    return result