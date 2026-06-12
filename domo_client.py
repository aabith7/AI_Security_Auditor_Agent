"""Thin wrapper around the Domo AppDB (Datastores) REST API."""
import json
import requests
from config import DOMO_BASE_URL, DOMO_DEVELOPER_TOKEN


class DomoAppDBClient:
    def __init__(self, base_url: str = DOMO_BASE_URL, token: str = DOMO_DEVELOPER_TOKEN):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"X-DOMO-Developer-Token": token})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    # ── basic operations ─────────────────────────────────

    def list_documents(self, collection_id: str) -> str:
        r = self.session.get(self._url(f"/v1/collections/{collection_id}/documents"))
        r.raise_for_status()
        return r.text

    def get_document(self, collection_id: str, document_id: str) -> str:
        r = self.session.get(
            self._url(f"/v1/collections/{collection_id}/documents/{document_id}")
        )
        r.raise_for_status()
        return r.text

    def query_documents(self, collection_id: str, query: dict) -> str:
        r = self.session.post(
            self._url(f"/v2/collections/{collection_id}/documents/query"),
            json=query,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        return r.text

    def delete_document(self, collection_id: str, document_id: str) -> str:
        r = self.session.delete(
            self._url(f"/v1/collections/{collection_id}/documents/{document_id}")
        )
        r.raise_for_status()
        return r.text or f"Document {document_id} deleted (status {r.status_code})"

    # ── smart find / delete by value ─────────────────────

    def find_documents_by_field(self, collection_id: str, field: str,
                                value, operator: str = "$eq") -> str:
        """Find documents where a content field matches a value.
        Auto-adds 'content.' prefix, handles string/number mismatch,
        and falls back to case-insensitive partial matching."""
        if not field.startswith("content."):
            field = f"content.{field}"

        docs = json.loads(self.query_documents(collection_id, {field: {operator: value}}))

        # fallback 1: type flip (string <-> number)
        if not docs and operator == "$eq":
            alt = None
            if isinstance(value, str) and value.isdigit():
                alt = int(value)
            elif isinstance(value, (int, float)):
                alt = str(value)
            if alt is not None:
                docs = json.loads(
                    self.query_documents(collection_id, {field: {operator: alt}})
                )

        # fallback 2: case-insensitive partial match (client-side)
        note = ""
        if not docs and operator == "$eq" and isinstance(value, str):
            all_docs = json.loads(self.list_documents(collection_id))
            plain_field = field.replace("content.", "", 1)
            needle = value.lower()
            docs = [
                d for d in all_docs
                if needle in str(d.get("content", {}).get(plain_field, "")).lower()
            ]
            if docs:
                note = (f"No exact match for '{value}'; "
                        f"showing case-insensitive partial matches.")

        matches = [
            {"document_id": d.get("id"), "content": d.get("content")} for d in docs
        ]
        return json.dumps(
            {"match_count": len(matches), "note": note, "documents": matches},
            indent=2,
        )

    def delete_documents_by_field(self, collection_id: str, field: str, value) -> str:
        """Find documents by field value, then delete each one by its ID."""
        found = json.loads(self.find_documents_by_field(collection_id, field, value))
        if found["match_count"] == 0:
            return f"No documents found where {field} = {value}. Nothing deleted."

        deleted = []
        for doc in found["documents"]:
            self.delete_document(collection_id, doc["document_id"])
            deleted.append(doc["document_id"])
        return json.dumps({"deleted_count": len(deleted), "deleted_ids": deleted})