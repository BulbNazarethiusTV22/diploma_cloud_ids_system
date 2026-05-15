from abc import ABC, abstractmethod
from io import BytesIO

from minio import Minio
from minio.error import S3Error

from config import (
    MINIO_ENDPOINT,
    MINIO_ACCESS_KEY,
    MINIO_SECRET_KEY,
    MINIO_BUCKET,
    MINIO_SECURE,
)


class CloudStorageAdapter(ABC):
    @abstractmethod
    def ensure_bucket_exists(self) -> None:
        pass

    @abstractmethod
    def upload_file(
        self,
        object_name: str,
        file_path: str,
        content_type: str = "application/octet-stream"
    ) -> None:
        pass

    @abstractmethod
    def list_files(self) -> list[dict]:
        pass

    @abstractmethod
    def download_file(self, object_name: str, file_path: str) -> None:
        pass

    @abstractmethod
    def delete_file(self, object_name: str) -> None:
        pass

    @abstractmethod
    def create_folder(self, folder_path: str) -> None:
        pass

    @abstractmethod
    def delete_folder(self, folder_path: str) -> dict:
        pass


class MinIOStorageAdapter(CloudStorageAdapter):
    def __init__(self):
        self.client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )

        self.bucket = MINIO_BUCKET

    def ensure_bucket_exists(self) -> None:
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
                print(f"Bucket created: {self.bucket}")
            else:
                print(f"Bucket already exists: {self.bucket}")

        except S3Error as e:
            print(f"MinIO error: {e}")
            raise

    def upload_file(
        self,
        object_name: str,
        file_path: str,
        content_type: str = "application/octet-stream"
    ) -> None:
        self.client.fput_object(
            self.bucket,
            object_name,
            file_path,
            content_type=content_type,
        )

    def list_files(self) -> list[dict]:
        objects = self.client.list_objects(
            self.bucket,
            recursive=True
        )

        return [
            {
                "filename": obj.object_name,
                "size": obj.size,
                "last_modified": str(obj.last_modified),
            }
            for obj in objects
        ]

    def download_file(self, object_name: str, file_path: str) -> None:
        self.client.fget_object(
            self.bucket,
            object_name,
            file_path,
        )

    def delete_file(self, object_name: str) -> None:
        self.client.remove_object(
            self.bucket,
            object_name,
        )

    def create_folder(self, folder_path: str) -> None:
        folder_path = folder_path.strip("/")

        if not folder_path:
            raise ValueError("Folder path cannot be empty")

        object_name = f"{folder_path}/.keep"

        self.client.put_object(
            self.bucket,
            object_name,
            BytesIO(b""),
            length=0,
            content_type="application/x-directory",
        )

    def delete_folder(self, folder_path: str) -> dict:
        folder_path = folder_path.strip("/")

        if not folder_path:
            raise ValueError("Folder path cannot be empty")

        prefix = folder_path + "/"

        objects = list(
            self.client.list_objects(
                self.bucket,
                prefix=prefix,
                recursive=True,
            )
        )

        deleted_count = 0
        deleted_bytes = 0

        for obj in objects:
            deleted_bytes += obj.size or 0
            self.client.remove_object(self.bucket, obj.object_name)
            deleted_count += 1

        return {
            "folder_path": folder_path,
            "deleted_objects": deleted_count,
            "deleted_bytes": deleted_bytes,
        }


storage = MinIOStorageAdapter()


def ensure_bucket_exists() -> None:
    storage.ensure_bucket_exists()


def upload_file(
    object_name: str,
    file_path: str,
    content_type: str = "application/octet-stream"
) -> None:
    storage.upload_file(object_name, file_path, content_type)


def list_files() -> list[dict]:
    return storage.list_files()


def download_file(object_name: str, file_path: str) -> None:
    storage.download_file(object_name, file_path)


def delete_file(object_name: str) -> None:
    storage.delete_file(object_name)


def create_folder(folder_path: str) -> None:
    storage.create_folder(folder_path)


def delete_folder(folder_path: str) -> dict:
    return storage.delete_folder(folder_path)
