# secure_file_client/offchain/index_manager.py

import json
from datetime import datetime, timezone

from ..exceptions import IndexManagementError

class IndexManager:


    @staticmethod
    def create_new_index() -> dict:
        return {
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "lastModified": datetime.now(timezone.utc).isoformat(),
            "files": []  # The list where file entries will be stored
        }

    @staticmethod
    def add_file_entry(index_data: dict, file_id: int, filename: str, custom_metadata: dict = None) -> dict:
        if "files" not in index_data or not isinstance(index_data["files"], list):
            raise IndexManagementError("Invalid index data format: 'files' list is missing.")

        new_entry = {
            "fileId": file_id,
            "filename": filename,
            "addedAt": datetime.now(timezone.utc).isoformat(),
            "metadata": custom_metadata or {}
        }

        if any(f.get("fileId") == file_id for f in index_data["files"]):
            raise IndexManagementError(f"File with ID {file_id} already exists in the index.")

        index_data["files"].append(new_entry)
        index_data["lastModified"] = datetime.now(timezone.utc).isoformat()
        
        return index_data

    @staticmethod
    def remove_file_entry(index_data: dict, file_id: int) -> dict:
        if "files" not in index_data or not isinstance(index_data["files"], list):
            raise IndexManagementError("Invalid index data format: 'files' list is missing.")

        initial_count = len(index_data["files"])
        index_data["files"] = [f for f in index_data["files"] if f.get("fileId") != file_id]
        
        if len(index_data["files"]) == initial_count:
            # This means no file was found with the given ID
            raise IndexManagementError(f"File with ID {file_id} not found in the index for removal.")

        index_data["lastModified"] = datetime.now(timezone.utc).isoformat()
        
        return index_data

    @staticmethod
    def to_json_bytes(index_data: dict) -> bytes:
        json_string = json.dumps(index_data, separators=(',', ':'), ensure_ascii=False)
        return json_string.encode('utf-8')

    @staticmethod
    def from_json_bytes(json_bytes: bytes) -> dict:
        try:
            return json.loads(json_bytes.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise IndexManagementError("Failed to decode index data from JSON bytes.") from e