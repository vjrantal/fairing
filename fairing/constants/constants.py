TEMP_TAR_GZ_FILENAME = '/tmp/fairing.layer.tar.gz'
DEFAULT_IMAGE_NAME = 'fairing-job'
DEFAULT_BASE_IMAGE = 'gcr.io/kubeflow-images-public/fairing:dev'
DEFAULT_REGISTRY = 'index.docker.io'
DEFAULT_DEST_PREFIX = '/app/'

DEFAULT_CONTEXT_FILENAME = '/tmp/fairing.context.tar.gz'
DEFAULT_GENERATED_DOCKERFILE_FILENAME = '/tmp/Dockerfile'

GOOGLE_CREDS_ENV = 'GOOGLE_APPLICATION_CREDENTIALS'
GCP_CREDS_SECRET_NAME = 'user-gcp-sa'

AWS_CREDS_SECRET_NAME = 'aws-secret'

AZURE_CREDS_SECRET_NAME = 'azure-credentials'
AZURE_STORAGE_CREDS_SECRET_NAME_PREFIX = 'storage-credentials-'
AZURE_ACR_CONFIG_CONFIGMAP_NAME = 'acr-config'

DEFAULT_USER_AGENT = 'kubeflow-fairing/{VERSION}'
