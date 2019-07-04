import json
import logging
import os
import base64
import tarfile

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccountCreateParameters
from azure.mgmt.storage.models import Sku
from azure.mgmt.storage.models import SkuName
from azure.mgmt.storage.models import Kind
from azure.storage.blob import BlockBlobService
from azure.storage.file import FileService
from fairing.constants import constants
from fairing.kubernetes.manager import KubeManager
from kubernetes import client
from pathlib import Path


logger = logging.getLogger(__name__)

class AzureFileUploader(object):
    def __init__(self, namespace):
        credentials = get_azure_credentials(namespace)
        sp_credentials = ServicePrincipalCredentials(
            client_id = credentials['clientId'],
            secret = credentials['clientSecret'],
            tenant = credentials['tenantId']
        ) 
        self.storage_client = StorageManagementClient(sp_credentials, credentials['subscriptionId'])
    
    def upload_to_share(self,
                        region,
                        resource_group_name,
                        storage_account_name,
                        share_name,
                        dir_name,
                        tar_gz_file_to_upload):
        
        logging.info(f"Uploading contents of '{tar_gz_file_to_upload}' to 'https://{storage_account_name}.file.core.windows.net/{share_name}/{dir_name}'")
        
        self.create_storage_account_if_not_exists(region, resource_group_name, storage_account_name)        
        storage_account_name, storage_key = self.get_storage_credentials(resource_group_name, storage_account_name)
        share_service = FileService(account_name=storage_account_name, account_key=storage_key)        
        self.create_share_if_not_exists(share_service, share_name)
        share_service.create_directory(share_name, dir_name)
        self.upload_tar_gz_contents(share_service, share_name, dir_name, tar_gz_file_to_upload)
        
        return storage_account_name, storage_key
        
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
            storage_async_operation.result()
    
    def get_storage_credentials(self, resource_group_name, storage_account_name):
        storage_keys = self.storage_client.storage_accounts.list_keys(resource_group_name, storage_account_name)
        storage_keys = {v.key_name: v.value for v in storage_keys.keys}
        
        return storage_account_name, storage_keys['key1']
    
    def create_share_if_not_exists(self, share_service, share_name):                        
        shares = share_service.list_shares()
        share = next(filter(lambda share: share.name == share_name, shares), None)      
        if (share is None):
            share_service.create_share(share_name)
    
    def upload_tar_gz_contents(self, share_service, share_name, dir_name, tar_gz_file):
        local_dir = Path(f'{tar_gz_file}_contents')
        cloud_dir = Path(dir_name)
        self.uncompress_tar_gz_file(tar_gz_file, local_dir)

        for path in local_dir.glob('**/*'):
            local_path = Path(path)
            cloud_relative_path = cloud_dir / path.relative_to(local_dir)

            if local_path.is_dir():
                share_service.create_directory(share_name, cloud_relative_path)
            else:
                share_service.create_file_from_path(share_name, cloud_relative_path.parents[0], cloud_relative_path.name, local_path)

    def uncompress_tar_gz_file(self, tar_gz_file, target_dir):        
        tar = tarfile.open(tar_gz_file, 'r:gz')
        tar.extractall(path=target_dir)
        tar.close()            
    
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
            + f"Secret {constants.AZURE_CREDS_SECRET_NAME} not found in namespace {namespace}")

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

def create_storage_creds_secret(namespace, context_hash, storage_account_name, storage_key):
    secret_name = constants.AZURE_STORAGE_CREDS_SECRET_NAME_PREFIX + context_hash.lower()
    logging.info(f"Creating secret {secret_name} in namespace {namespace}")
    secret = client.V1Secret(
        metadata = client.V1ObjectMeta(name=secret_name),
        string_data={
            'azurestorageaccountname': storage_account_name,
            'azurestorageaccountkey': storage_key
        })
    v1 = client.CoreV1Api()
    v1.create_namespaced_secret(namespace, secret)
        
def delete_storage_creds_secret(namespace, context_hash):
    secret_name = constants.AZURE_STORAGE_CREDS_SECRET_NAME_PREFIX + context_hash.lower()
    logging.info(f"Deleting secret {secret_name} from namespace {namespace}")
    v1 = client.CoreV1Api()
    v1.delete_namespaced_secret(secret_name, namespace)
        
def add_acr_config(kube_manager, pod_spec, namespace):
    volume_mount=client.V1VolumeMount(
            name='docker-config', mount_path='/kaniko/.docker/', read_only=True)

    if pod_spec.containers[0].volume_mounts:
        pod_spec.containers[0].volume_mounts.append(volume_mount)
    else:
        pod_spec.containers[0].volume_mounts = [volume_mount]

    volume=client.V1Volume(
            name='docker-config',
            config_map=client.V1ConfigMapVolumeSource(name='acr-config'))

    if pod_spec.volumes:
        pod_spec.volumes.append(volume)
    else:
        pod_spec.volumes = [volume]

def add_azure_files(kube_manager, pod_spec, namespace):
    context_hash = pod_spec.containers[0].args[1].split(':')[-1]
    secret_name = constants.AZURE_STORAGE_CREDS_SECRET_NAME_PREFIX + context_hash.lower()
    volume_mount=client.V1VolumeMount(
        name='azure', mount_path='/mnt/azure', read_only=True)
                         
    if pod_spec.containers[0].volume_mounts:
        pod_spec.containers[0].volume_mounts.append(volume_mount)
    else:
        pod_spec.containers[0].volume_mounts = [volume_mount]

    volume=client.V1Volume(
            name='azure',
            azure_file=client.V1AzureFileVolumeSource(secret_name=secret_name, share_name='fairing-builds'))
                         
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
def get_azure_credentials(namespace):
    secret_name = constants.AZURE_CREDS_SECRET_NAME
    if KubeManager().secret_exists(secret_name, namespace):
        v1 = client.CoreV1Api()
        secret = v1.read_namespaced_secret(secret_name, namespace)
        secret_base64 = list(secret.data.values())[0]
        secret_json = base64.b64decode(secret_base64).decode('utf-8')
        return json.loads(secret_json)

def create_acr_registry(registry, repository, namespace):    
    # Authenticate with the Azure Management Libraries for Python
    # https://docs.microsoft.com/en-us/python/azure/python-sdk-azure-authenticate?view=azure-python
    credentials = get_azure_credentials(namespace)
    sp_credentials = ServicePrincipalCredentials(
        client_id = credentials['clientId'],
        secret = credentials['clientSecret'],
        tenant = credentials['tenantId']
    ) 
    client = ContainerRegistryManagementClient(sp_credentials, credentials['subscriptionId'])
    # TODO ME create the registry