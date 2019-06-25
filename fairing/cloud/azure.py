import json
import logging
import os

from azure.common.client_factory import get_client_from_auth_file
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.storage import StorageManagementClient
from fairing.constants import constants
from kubernetes import client

logger = logging.getLogger(__name__)


class AzureUploader(object):
    def __init__(self):
        self.storage_client = get_client_from_auth_file(StorageManagementClient)

    def upload_to_container(self,
                            region,
                            storage_account_name,
                            container_name,
                            blob_name,
                            file_to_upload):
        block_blob_service = self.get_or_create_container(region, storage_account_name, container_name)
        block_blob_service.create_blob_from_path(container_name, blob_name, file_to_upload)
        # TODO ME what do we return here?
        return f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{blob_name}"

    def get_or_create_container(self, region, storage_account_name, container_name):
        # TODO ME
        # if storage account doesn't exist
        # create storage account in region
        # if container doesn't exist
        # create container
        # get key using storage_client
        # instantiate BlockBlobService with storage_account_name and key
        # return BlockBlobService
        pass


# TODO ME review: what's a project id in Azure context? \
def guess_project_name(credentials_file=None):
    pass


def add_azure_credentials_if_exists(kube_manager, pod_spec, namespace):
    try:
        if kube_manager.secret_exists(constants.AZURE_CREDS_SECRET_NAME, namespace):
            add_azure_credentials(kube_manager, pod_spec, namespace)
        else:
            logger.warning(f"Not able to find Azure credentials secret: {constants.AZURE_CREDS_SECRET_NAME}")
    except Exception as e:
        logger.warn(f"could not check for secret: {e}")


def add_azure_credentials(kube_manager, pod_spec, namespace):
    if not kube_manager.secret_exists(constants.AZURE_CREDS_SECRET_NAME, namespace):
        raise ValueError("Unable to mount credentials: "
            + f"Secret {constants.AZURE_CREDS_SECRET_NAME} found in namespace {namespace}")

    # Set appropriate secrets and volumes to enable kubeflow-user service
    # account.
    env_var = client.V1EnvVar(
        name='AZURE_AUTH_LOCATION',
        value='/etc/secrets/azure-credentials.json')
    if pod_spec.containers[0].env:
        pod_spec.containers[0].env.append(env_var)
    else:
        pod_spec.containers[0].env = [env_var]

    volume_mount = client.V1VolumeMount(
        name='azure-credentials', mount_path='/etc/secrets', read_only=True)
    if pod_spec.containers[0].volume_mounts:
        pod_spec.containers[0].volume_mounts.append(volume_mount)
    else:
        pod_spec.containers[0].volume_mounts = [volume_mount]

    volume = client.V1Volume(
        name='azure-credentials',
        secret=client.V1SecretVolumeSource(secret_name=constants.AZURE_CREDS_SECRET_NAME))
    if pod_spec.volumes:
        pod_spec.volumes.append(volume)
    else:
        pod_spec.volumes = [volume]

# TODO ME depends on the guess_project_name, deal with that
def get_default_docker_registry():
    try:
        return f"{guess_project_name()}.azurecr.io/fairing-job"
    except:
        return None


def add_acr_config(kube_manager, pod_spec, namespace):
    if not kube_manager.secret_exists('acr-config', namespace):
        secret = client.V1Secret(
            metadata = client.V1ObjectMeta(name='acr-config'),
            string_data={
                'config.json': '{"credsStore": "acr-login"}'
            })
        kube_manager.create_secret(namespace, secret)

    volume_mount=client.V1VolumeMount(
            name='acr-config', mount_path='/kaniko/.docker/', read_only=True)

    if pod_spec.containers[0].volume_mounts:
        pod_spec.containers[0].volume_mounts.append(volume_mount)
    else:
        pod_spec.containers[0].volume_mounts = [volume_mount]

    volume=client.V1Volume(
            name='acr-config',
            secret=client.V1SecretVolumeSource(secret_name='acr-config'))

    if pod_spec.volumes:
        pod_spec.volumes.append(volume)
    else:
        pod_spec.volumes = [volume]


def is_acr_registry(registry):
    return registry.endswith(".azurecr.io")

def create_acr_registry(registry, repository):
    acr_client = get_client_from_auth_file(ContainerRegistryManagementClient)
    # TODO ME create the registry