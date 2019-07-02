import os
import uuid

from fairing import utils
from fairing.builders.cluster.context_source import ContextSourceInterface
from fairing.cloud import azure
from fairing.constants import constants
from fairing.kubernetes.manager import client


class StorageContextSource(ContextSourceInterface):
    def __init__(self, region=None, resource_group_name=None, storage_account_name=None, share_name=None):
        self.region = region or "WestEurope"
        self.resource_group_name = resource_group_name or "fairing"
        # TODO ME note that the generated name is not necessarily unique due to truncation...
        self.storage_account_name = storage_account_name or f"{uuid.uuid4().hex[:24]}"
        self.share_name = share_name or "fairing-builds"

    def prepare(self, context_filename):
        self.context_path = self.upload_context(context_filename)

    def upload_context(self, context_filename):
        azure_uploader = azure.AzureFileUploader()
        context_hash = utils.crc(context_filename)
        dir_name = f'build_{context_hash}'
        azure_uploader.upload_to_share(
                    self.region,
                    self.resource_group_name,
                    self.storage_account_name,
                    self.share_name,
                    dir_name=dir_name,
                    tar_gz_file_to_upload=context_filename)
        return f'/mnt/azure/{dir_name}/'
    
    def cleanup(self):
        pass

    def generate_pod_spec(self, image_name, push):
        args = [f"--dockerfile=Dockerfile",
                          "--destination=" + image_name,
                          "--context=" + self.context_path]
        if not push:
            args.append("--no-push")
        return client.V1PodSpec(
                containers=[client.V1Container(
                    name='kaniko',
                    image='gcr.io/kaniko-project/executor:v0.7.0',
                    args=["--dockerfile=Dockerfile",
                          "--destination=" + image_name,
                          "--context=" + self.context_path],
                )],
                restart_policy='Never'
            )