#!/usr/bin/env bash

# Obtain IMDS token for querying instance metadata
imds_token=$(curl -Ss -H "X-aws-ec2-metadata-token-ttl-seconds: 30" -XPUT 169.254.169.254/latest/api/token)
instance_id=$(curl -Ss -H "X-aws-ec2-metadata-token: $imds_token" 169.254.169.254/latest/meta-data/instance-id)
local_ipv4=$(curl -Ss -H "X-aws-ec2-metadata-token: $imds_token" 169.254.169.254/latest/meta-data/local-ipv4)

# Install necessary packages
curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
apt-get update
apt-get install -y vault=${VAULT_VERSION}-* awscli jq

# Configure system time
echo "Configuring system time"
timedatectl set-timezone UTC

# Remove any default installation files from /opt/vault/tls/
rm -rf /opt/vault/tls/*

# Ensure /opt/vault/tls directory is readable by all users
chmod 0755 /opt/vault/tls

# Write Cloudflare certificates to files
echo "${CLOUD_FLARE_CERT}" > /opt/vault/tls/vault-cert.pem
echo "${CLOUD_FLARE_KEY}" > /opt/vault/tls/vault-key.pem

# Add Cloudflare Origin CA Root certificate directly
cat << 'EOF' > /opt/vault/tls/vault-ca.pem
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIRAN6s8sVglCvT3PoUQUtrqQYwDQYJKoZIhvcNAQELBQAw
VzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUlzc3VpbmdNYW5pZmVzdDEfMB0GA1UE
CxMWQ2xvdWRmbGFyZSBDZXJ0aWZpY2F0ZTETMBEGA1UEAxMKQ2xvdWRmbGFyZTAe
Fw0xNDA0MjgyMTI2MDBaFw0zNDA0MjgyMTM2MDBaMFcxCzAJBgNVBAYTAlVTMRYw
FAYDVQQKEw1Jc3N1aW5nTWFuaWZlc3QxHzAdBgNVBAsTFkNsb3VkZmxhcmUgQ2Vy
dGlmaWNhdGUxEzARBgNVBAMTCkNsb3VkZmxhcmUwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCxlN6EO/nrY9NOmDglJx5SM3hgk3Efx5zz2te/N2rgduqN
l2LbbqCnOqv+MST5pEroaYuqE+qXfGZlh1T8en5sT1ZfbxeiS8QyyhDwW5bZP6Nf
/zCLp0HZyg9e7nX70ZEF71EJaF6qZAPGRopnPtnmHdO0mjHRN65tDkx3IWlK6eU8
tOFvMoxABiJEDLoBbATaU/yN1J8J53TjWn3FA9Z5Cebws6kMdEsmdpqM36h7Yaey
Wph9BNMm0gkDgjKkvBr82moVGX0jI5ew/CGTyQbGKoTp0VCCXa0afG9eUkE5xXoz
N0HJq/T2dsf99Vw3/MZxyFaOwFln6LfGJCI2aVn7AgMBAAGjUDBOMB0GA1UdDgQW
BBT8zRVK5EXlQMjYBFR7oAWkF5pVKDAfBgNVHSMEGDAWgBT8zRVK5EXlQMjYBFR7
oAWkF5pVKDAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAQEAUl9P
i+F9qBfOh7Q4+ay1D8R9PVO4cKZqllyKhJ9KpBLnT+PwvYX9KN6twaJ82yuCMbop
AOklM9O8BOAkFN9t16DwHKY6m65cFqaIM+wET4dbIh8+2dnCkHlTG0hzFsmIjpxN
/dnbqKNFSOdMywZlOa82h7yO4m8iR2E59fVlx+AYyDQ7BZx6z2RBrZVxtCKFC0jA
BBAeH4yf9H5PxFxu1lGGZz5DjF9QJkb6On2AeB4VRqv2+d9T5ukWXN7OSoJmxH/W
tyUwRmw1qXBHNCqYl5sLe+nKtugy0XhApDWFOoyByUDfbNnGGOEDT1rIdGV33PTz
fTbhKiK/fn0K+nMc9H+pRw==
-----END CERTIFICATE-----
EOF

# Set ownership and permissions
chown vault:vault /opt/vault/tls/vault-key.pem /opt/vault/tls/vault-cert.pem /opt/vault/tls/vault-ca.pem
chmod 640 /opt/vault/tls/vault-key.pem
chmod 644 /opt/vault/tls/vault-cert.pem
chmod 644 /opt/vault/tls/vault-ca.pem
