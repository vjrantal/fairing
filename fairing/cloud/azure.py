import json
import logging
import os
import base64

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters
from azure.mgmt.storage.models import Sku
from azure.mgmt.storage.models import SkuName
from azure.mgmt.storage.models import Kind
from azure.storage.blob import BlockBlobService
from fairing.constants import constants
from fairing.kubernetes.manager import KubeManager
from kubernetes import client

logger = logging.getLogger(__name__)

class AzureUploader(object):
    def __init__(self):
        credentials = get_azure_credentials(constants.AZURE_CREDS_SECRET_NAME, 'kubeflow')
        sp_credentials = ServicePrincipalCredentials(
            client_id = credentials['clientId'],
            secret = credentials['clientSecret'],
            tenant = credentials['tenantId']
        ) 
        self.storage_client = StorageManagementClient(sp_credentials, credentials['subscriptionId'])

    def upload_to_container(self,
                            region,
                            resource_group_name,
                            storage_account_name,
                            container_name,
                            blob_name,
                            file_to_upload):
        block_blob_service = self.get_or_create_container(region, resource_group_name, storage_account_name, container_name)
        block_blob_service.create_blob_from_path(container_name, blob_name, file_to_upload)
        # TODO ME what do we return here?
        return f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{blob_name}"

    def get_or_create_container(self, region, resource_group_name, storage_account_name, container_name):
        self.create_storage_account_if_not_exists(region, resource_group_name, storage_account_name)

        storage_keys = self.storage_client.storage_accounts.list_keys(resource_group_name, storage_account_name)
        storage_keys = {v.key_name: v.value for v in storage_keys.keys}
        block_blob_service = BlockBlobService(account_name=storage_account_name, account_key=storage_keys['key1'])
        containers = block_blob_service.list_containers()
        container = next(filter(lambda container: container.name == container_name, containers), None)
        
        if (container is None):
            result = block_blob_service.create_container(container_name)

        return block_blob_service
    
    def create_storage_account_if_not_exists(self, region, resource_group_name, storage_account_name):
        # Creation should succeed even if the storage account exists, but if it exists I get error "The property 'isHnsEnabled' was specified in the input, but it cannot be updated."
        storage_accounts = self.storage_client.storage_accounts.list_by_resource_group(resource_group_name)
        storage_account = next(filter(lambda storage_account: storage_account.name == storage_account_name, storage_accounts), None)
        
        if (storage_account is None):    
            storage_async_operation = self.storage_client.storage_accounts.create(
                resource_group_name,
                storage_account_name,
                StorageAccountCreateParameters(
                    sku=Sku(name=SkuName.standard_ragrs),
                    kind=Kind.storage,
                    location=region
                )
            )
            storage_account = storage_async_operation.result()
            
        return storage_account

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

# To generate a credentials file for a service principal:
#    az ad sp create-for-rbac --scope /subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP_NAME} --sdk-auth > ${FILE_NAME}
# To set a secret in k8s cluster containing the file:
#    kubectl create secret generic azure-credentials -n kubeflow --from-file=azure-credentials.json=${FILE_NAME}
# where you should update the variables ${SUBSCRIPTION_ID}, ${RESOURCE_GROUP_NAME}, and ${FILE_NAME}
def get_azure_credentials(secret_name, namespace):
    if KubeManager().secret_exists(secret_name, namespace):
        v1 = client.CoreV1Api()
        secret = v1.read_namespaced_secret(secret_name, namespace)
        secret_base64 = list(secret.data.values())[0]
        secret_json = base64.b64decode(secret_base64).decode('utf-8')
        return json.loads(secret_json)

def create_acr_registry(registry, repository):    
    # Authenticate with the Azure Management Libraries for Python
    # https://docs.microsoft.com/en-us/python/azure/python-sdk-azure-authenticate?view=azure-python
    credentials = get_azure_credentials(constants.AZURE_CREDS_SECRET_NAME, 'kubeflow')
    sp_credentials = ServicePrincipalCredentials(
        client_id = credentials['clientId'],
        secret = credentials['clientSecret'],
        tenant = credentials['tenantId']
    ) 
    client = ContainerRegistryManagementClient(sp_credentials, credentials['subscriptionId'])
    # TODO ME create the registry