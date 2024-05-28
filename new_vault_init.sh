#!/bin/bash
set -e

# Fetch instance metadata
imds_token=$(curl -Ss -H "X-aws-ec2-metadata-token-ttl-seconds: 30" -X PUT "http://169.254.169.254/latest/api/token")
instance_id=$(curl -Ss -H "X-aws-ec2-metadata-token: $imds_token" "http://169.254.169.254/latest/meta-data/instance-id")
local_ipv4=$(curl -Ss -H "X-aws-ec2-metadata-token: $imds_token" "http://169.254.169.254/latest/meta-data/local-ipv4")

# Install Vault and other necessary packages
curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update
apt-get install -y vault awscli jq

# Configure system time
timedatectl set-timezone UTC

# Create necessary directories
mkdir -p /opt/vault/tls /etc/vault.d /opt/vault/data

# Copy the CA bundle, certificate, and key to the appropriate directory
cat <<EOF > /opt/vault/tls/vault-cert.pem
-----BEGIN CERTIFICATE-----
... (Your certificate here) ...
-----END CERTIFICATE-----
EOF

cat <<EOF > /opt/vault/tls/vault-key.pem
-----BEGIN PRIVATE KEY-----
... (Your private key here) ...
-----END PRIVATE KEY-----
EOF

cat <<EOF > /opt/vault/tls/vault-ca.pem
-----BEGIN CERTIFICATE-----
... (Your CA bundle here) ...
-----END CERTIFICATE-----
EOF

# Set permissions for the TLS files
chown -R root:vault /opt/vault/tls
chmod 640 /opt/vault/tls/*

# Create the Vault configuration file
cat <<EOF > /etc/vault.d/vault.hcl
ui = true
disable_mlock = true

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "$instance_id"
}

listener "tcp" {
  address            = "0.0.0.0:8200"
  tls_disable        = false
  tls_cert_file      = "/opt/vault/tls/vault-cert.pem"
  tls_key_file       = "/opt/vault/tls/vault-key.pem"
  tls_client_ca_file = "/opt/vault/tls/vault-ca.pem"
}

seal "awskms" {
  region     = "${region}"
  kms_key_id = "${kms_key_arn}"
}

cluster_addr = "https://$local_ipv4:8201"
api_addr = "https://$local_ipv4:8200"
EOF

# Set permissions for the Vault configuration file
chown root:vault /etc/vault.d/vault.hcl
chmod 640 /etc/vault.d/vault.hcl

# Enable and start Vault
systemctl enable vault
systemctl start vault

# Wait for Vault to start
sleep 10

# Initialize Vault and store unseal keys and root token in AWS Secrets Manager
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="/opt/vault/tls/vault-ca.pem"

if ! vault status | grep -q 'Initialized.*true'; then
  echo "Initializing Vault..."
  init_output=$(vault operator init -format=json)
  
  unseal_keys=$(echo "$init_output" | jq -r '.unseal_keys_b64[]' | jq -sc .)
  root_token=$(echo "$init_output" | jq -r '.root_token')
  
  secret_payload=$(jq -n --arg unseal_keys "$unseal_keys" --arg root_token "$root_token" '{unseal_keys: $unseal_keys, root_token: $root_token}')
  
  aws secretsmanager create-secret --name "vault-unseal-keys" --secret-string "$secret_payload" --region "${region}"
  
  echo "Vault initialized and keys stored in AWS Secrets Manager."
else
  echo "Vault is already initialized."
fi

# Setup Vault profile
cat <<EOF > /etc/profile.d/vault.sh
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="/opt/vault/tls/vault-ca.pem"
EOF
