from abc import ABC, abstractmethod


class CloudStorageAdapter(ABC):

    @abstractmethod
    def upload_file(self, object_name: str, file_path: str, content_type: str):
        pass

    @abstractmethod
    def list_files(self) -> list[dict]:
        pass

    @abstractmethod
    def download_file(self, object_name: str, file_path: str):
        pass

    @abstractmethod
    def delete_file(self, object_name: str):
        pass

    @abstractmethod
    def create_folder(self, folder_path: str):
        pass

    @abstractmethod
    def delete_folder(self, folder_path: str) -> dict:
        pass
