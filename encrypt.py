import json
import logging
from flask import Flask, request, jsonify
from google.cloud import secretmanager, storage
import gnupg

# Initialize Flask app
encyprtion_over_cloud_run = Flask(__name__)

# Initialize clients and services
storage_client = storage.Client()
gpg = gnupg.GPG()
logging.basicConfig(level=logging.INFO)

def fetch_secret(secret_id):
    """
    Fetches the secret details from Google Cloud Secret Manager.
    """
    client = secretmanager.SecretManagerServiceClient()
    secret_name = f"{secret_id}/versions/latest"
    try:
        response = client.access_secret_version({"name": secret_name})
        secret_data = response.payload.data.decode("UTF-8")
        logging.info(f"Successfully fetched secret: {secret_id}")
        return secret_data
    except Exception as e:
        logging.error(f"Failed to fetch secret for key: {secret_id}. Error: {e}")
        raise

def fetch_conf_details(bucket_name, conf_file_name):
    """
    Reads the configuration file from Google Cloud Storage and returns its contents.
    """
    logging.info(f"Reading config file from GCS: {conf_file_name}")
    bucket = storage_client.bucket(bucket_name)
    try:
        blob = bucket.blob(conf_file_name)
        conf_content = blob.download_as_text()
        logging.info(f"Successfully read config file: {conf_file_name}")
        return conf_content
    except Exception as e:
        logging.error(f"Failed to read config file: {conf_file_name}. Error: {e}")
        raise

def read_and_encrypt_data(bucket_name, file_path, file_name, gpg_public_key, recipient_name):
    """
    Reads the file from GCS, encrypts it using GnuPG, and returns the encrypted data.
    """
    try:
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_path + file_name)
        data_to_encrypt = blob.download_as_text()
        logging.info(f"Successfully read file: {file_name} from bucket: {bucket_name}")
    except Exception as e:
        logging.error(f"Failed to read file: {file_name} from bucket: {bucket_name}. Error: {e}")
        raise

    try:
        gpg.import_keys(gpg_public_key)
        encrypted_data = gpg.encrypt(data_to_encrypt, recipients=[recipient_name], always_trust=True)
        if not encrypted_data.ok:
            raise ValueError(f"Encryption failed: {encrypted_data.stderr}")
        logging.info("Encryption successful")
        return encrypted_data
    except Exception as e:
        logging.error(f"Failed to encrypt data. Error: {e}")
        raise

def upload_encrypted_data(bucket_name, encrypted_data, encrypted_file_path, file_name):
    """
    Uploads the encrypted data to Google Cloud Storage.
    """
    try:
        bucket = storage_client.bucket(bucket_name)
        encrypted_blob = bucket.blob(encrypted_file_path + file_name + ".asc")
        encrypted_blob.upload_from_string(str(encrypted_data))
        logging.info("Encrypted file stored to GCS bucket successfully!")
    except Exception as e:
        logging.error(f"Failed to upload encrypted data to GCS. Error: {e}")
        raise

@encyprtion_over_cloud_run.route("/encryption", methods=['GET'])
def encrypt():
    """
    Endpoint to handle the encryption process based on configuration provided in the request.
    """
    try:
        conf_path = request.args.get('conf_path')
        logging.info(f"Reading config file from path: {conf_path}")
        bucket_name = conf_path.split("/")[2]
        conf_file_name = conf_path.split(bucket_name, 1)[1].lstrip('/')
    except Exception as e:
        logging.error(f"Invalid configuration path: {conf_path}. Error: {e}")
        return jsonify({"error": f"Invalid configuration path: {e}"}), 400

    try:
        conf_details = fetch_conf_details(bucket_name, conf_file_name)
        conf = json.loads(conf_details)
        gpg_public_key = fetch_secret(conf['gpg_public_key'])
        gcs_bucket = fetch_secret(conf['gcs_bucket'])
        recipient_name = fetch_secret(conf['recipient_name'])
        file_name = conf['file_name']
        file_path = conf['file_path']
        encrypted_file_path = conf['encrypted_file_path']
    except Exception as e:
        logging.error(f"Failed to fetch configuration or secrets. Error: {e}")
        return jsonify({"error": f"Failed to fetch configuration or secrets: {e}"}), 500

    try:
        encrypted_data = read_and_encrypt_data(gcs_bucket, file_path, file_name, gpg_public_key, recipient_name)
    except Exception as e:
        logging.error(f"Failed during encryption. Error: {e}")
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    try:
        upload_encrypted_data(gcs_bucket, encrypted_data, encrypted_file_path, file_name)
    except Exception as e:
        logging.error(f"Failed to store encrypted file. Error: {e}")
        return jsonify({"error": f"Failed to store encrypted file: {e}"}), 500

    return jsonify({"message": "Success, file was encrypted and stored in GCS."})

# Run the app
if __name__ == "__main__":
    encyprtion_over_cloud_run.run(host="0.0.0.0", port=8080)