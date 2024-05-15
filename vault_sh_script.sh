Content-Type: multipart/mixed; boundary="==BOUNDARY=="
MIME-Version: 1.0

--==BOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -e

# Run Order: 1
# Run Frequency: only once, on first boot

# Install dependencies
yum update -y
yum install -y jq unzip

# Create the vault user
useradd --system --shell /sbin/nologin vault

# Create directories
mkdir -p /opt/vault
mkdir -p /opt/vault/bin
mkdir -p /opt/vault/config
mkdir -p /opt/vault/tls

# Set permissions and ownership
chmod 755 /opt/vault
chmod 755 /opt/vault/bin
chown -R vault:vault /opt/vault

# Get the HashiCorp PGP key
curl https://keybase.io/hashicorp/pgp_keys.asc | gpg --import

# Download Vault and signatures
VAULT_VERSION="1.8.4" # Ensure this variable is set correctly
curl -Os https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip
curl -Os https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS
curl -Os https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS.sig

# Verify signatures
gpg --verify vault_${VAULT_VERSION}_SHA256SUMS.sig vault_${VAULT_VERSION}_SHA256SUMS
cat vault_${VAULT_VERSION}_SHA256SUMS | grep vault_${VAULT_VERSION}_linux_amd64.zip | sha256sum -c

# Unzip and move to /opt/vault/bin
unzip vault_${VAULT_VERSION}_linux_amd64.zip
mv vault /opt/vault/bin/vault

# Give ownership to the vault user
chown vault:vault /opt/vault/bin/vault

# Create a symlink
ln -s /opt/vault/bin/vault /usr/local/bin/vault

# Allow vault permissions to use mlock and prevent memory from swapping to disk
setcap cap_ipc_lock=+ep /opt/vault/bin/vault

# Cleanup files
rm vault_${VAULT_VERSION}_linux_amd64.zip
rm vault_${VAULT_VERSION}_SHA256SUMS
rm vault_${VAULT_VERSION}_SHA256SUMS.sig

--==BOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -e

# Run Order: 2
# Run Frequency: only once, on first boot

# Fetch needed data and create self-signed certificate and key

INSTANCE_IP_ADDR=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
INSTANCE_DNS_NAME=$(curl http://169.254.169.254/latest/meta-data/local-hostname)

# Create self-signed certificate for Vault
openssl req -x509 -sha256 -nodes \
  -newkey rsa:4096 -days 3650 \
  -keyout /opt/vault/tls/vault.key -out /opt/vault/tls/vault.crt \
  -subj "/CN=$INSTANCE_DNS_NAME" \
  -extensions san \
  -config <(cat /etc/pki/tls/openssl.cnf <(echo -e "\n[san]\nsubjectAltName=DNS:$INSTANCE_DNS_NAME,IP:$INSTANCE_IP_ADDR"))

# Set ownership and permissions
chown vault:vault /opt/vault/tls/vault.key /opt/vault/tls/vault.crt
chmod 640 /opt/vault/tls/vault.key
chmod 644 /opt/vault/tls/vault.crt

# Trust the certificate
cp /opt/vault/tls/vault.crt /etc/pki/tls/certs/vault.crt

--==BOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -e

# Run Order: 3
# Run Frequency: only once, on first boot

# Create the Vault configuration file and systemd service file

cat > /opt/vault/config/server.hcl <<- EOF
cluster_name = "${VAULT_CLUSTER_NAME}"
max_lease_ttl = "192h"
default_lease_ttl = "192h"
ui  = "true"

# Where can the Vault API be reached?  At DNS for the load balancer, or the CNAME created.
api_addr = "https://${VAULT_DNS}"

# For forwarding between vault servers.  Set to own ip.
cluster_addr = "https://INSTANCE_IP_ADDR:8201"

# Auto unseal the vault
seal "awskms" {
  region = "${VAULT_CLUSTER_REGION}"
  kms_key_id = "${VAULT_KMS_KEY_ID}"
}

# Listener for loopback
listener "tcp" {
  address = "127.0.0.1:8199"
  tls_disable = "true"
}

# Listener for private network
listener "tcp" {
  address = "INSTANCE_IP_ADDR:8200"
  cluster_address = "INSTANCE_IP_ADDR:8201"

  tls_disable = "false"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file = "/opt/vault/tls/vault.key"
}

storage "dynamodb" {
  ha_enabled = "true"
  region = "${VAULT_CLUSTER_REGION}"
  table = "${VAULT_DYNAMODB_TABLE}"
}
EOF

# Replace placeholder with actual instance IP
sed -i -e "s/INSTANCE_IP_ADDR/$INSTANCE_IP_ADDR/g" /opt/vault/config/server.hcl

# Set ownership
chown vault:vault /opt/vault/config/server.hcl

# Create systemd service file for Vault
cat > /etc/systemd/system/vault.service <<- EOF
[Unit]
Description=Vault Server on AWS
Requires=network-online.target
After=network-online.target

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/opt/vault/bin/vault server -config=/opt/vault/config/ -log-level=info
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

--==BOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -e

# Run Order: 4
# Run Frequency: only once, on first boot

# Replace values in configuration files with instance metadata and start Vault

INSTANCE_IP_ADDR=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
sed -i -e "s/INSTANCE_IP_ADDR/$INSTANCE_IP_ADDR/g" /opt/vault/config/server.hcl

# Reload systemd and start Vault
systemctl daemon-reload
systemctl enable vault
systemctl restart vault

--==BOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
set -e

# Run Order: 5
# Run Frequency: only once, on first boot

# Initialize Vault, create credentials file, encrypt it, upload to S3, and clean up

# Wait to ensure the Vault service is fully initialized
sleep 20

export VAULT_ADDR="http://127.0.0.1:8199"
export AWS_DEFAULT_REGION="${VAULT_CLUSTER_REGION}"
export VAULT_INITIALIZED=$(vault operator init -status) # avoid non-zero exit status

initialize_vault() {
  # Initialize Vault and save credentials to a file
  vault operator init > vault_credentials.txt

  # Encrypt the credentials file with the KMS key
  aws kms encrypt --key-id ${VAULT_KMS_KEY_ID} --plaintext fileb://vault_credentials.txt --output text --query CiphertextBlob | base64 --decode > vault_creds_encrypted

  # Upload the encrypted file to the S3 bucket
  aws s3 cp vault_creds_encrypted s3://${VAULT_S3_BUCKET_NAME}/

  # Clean up
  rm vault_credentials.txt
  rm vault_creds_encrypted
  history -c
  history -w
}

if [ "$VAULT_INITIALIZED" = "Vault is initialized" ]; then
  echo "Vault is already initialized."
else
  echo "Initializing vault..."
  initialize_vault
fi

--==BOUNDARY==--
