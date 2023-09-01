from minio import Minio
import os




MINIO_CONNECTION_ENDPOINT = os.environ.get('MINIO_CONNECTION_ENDPOINT')	
MINIO_CONNECTION_USER = os.environ.get('MINIO_CONNECTION_USER')	
MINIO_CONNECTION_PASSWORD = os.environ.get('MINIO_CONNECTION_PASSWORD')	

minio_client = Minio( 
    MINIO_CONNECTION_ENDPOINT,
    access_key = MINIO_CONNECTION_USER,
    secret_key = MINIO_CONNECTION_PASSWORD,
    secure = True 
)