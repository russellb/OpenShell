# Manual E2E Test: S3 Access via STS Credentials

This guide walks through an end-to-end test of an OpenShell sandbox accessing
AWS S3 using gateway-minted STS temporary credentials with proxy-side SigV4
re-signing. The sandbox never sees real AWS credentials — the proxy resolves
placeholders and signs requests on the fly.

## Prerequisites

- AWS CLI authenticated (`aws sts get-caller-identity` succeeds)
- Podman running (`podman info` succeeds)
- OpenShell built from the `feat/1576-aws-sts-with-sigv4` branch (or later,
  once merged)

## 1. Create AWS test resources

Create an S3 bucket and an IAM role the gateway can assume:

```shell
BUCKET="openshell-sts-test-$(date +%s)"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws s3 mb "s3://${BUCKET}" --region us-east-1

aws iam create-role \
  --role-name openshell-sts-test-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::'${ACCOUNT}':root"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \
  --role-name openshell-sts-test-role \
  --policy-name s3-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::'${BUCKET}'", "arn:aws:s3:::'${BUCKET}'/*"]
    }]
  }'
```

Verify the role works:

```shell
aws sts assume-role \
  --role-arn "arn:aws:iam::${ACCOUNT}:role/openshell-sts-test-role" \
  --role-session-name test \
  --query Credentials.AccessKeyId --output text
```

## 2. Build the supervisor image

The supervisor image must include the SigV4 re-signing code and the updated
proto definitions. Build it from the branch:

```shell
CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run build:docker:supervisor
```

Verify the image exists locally:

```shell
podman images | grep "openshell/supervisor.*dev"
```

## 3. Start the gateway

The gateway needs AWS credentials in its environment to call `sts:AssumeRole`.
Export them before starting:

```shell
eval "$(aws configure export-credentials --format env)"
```

The gateway must use the local supervisor image. Edit the gateway config
(`~/.cache/gateway-podman/gateway.toml` or equivalent) so `supervisor_image`
appears under `[openshell.gateway]`:

```toml
[openshell.gateway]
supervisor_image = "localhost/openshell/supervisor:dev"
```

Then start the gateway:

```shell
mise run gateway
```

Alternatively, start the gateway binary directly with the correct config:

```shell
eval "$(aws configure export-credentials --format env)"
./target/debug/openshell-gateway \
  --config .cache/gateway-podman/gateway.toml \
  --port 18080 --log-level info --drivers podman --disable-tls \
  --db-url "sqlite:.cache/gateway-podman/gateway.db?mode=rwc"
```

## 4. Configure the provider

In a separate terminal:

```shell
export OPENSHELL_BASE_URL=http://localhost:18080

# Enable provider v2 (required for STS)
openshell settings set --global --key providers_v2_enabled --value true --yes

# Create the provider with the aws-s3 profile
openshell provider create --name s3-test --type aws-s3 \
  --credential AWS_ACCESS_KEY_ID=placeholder

# Configure STS refresh
openshell provider refresh configure s3-test \
  --credential-key AWS_ACCESS_KEY_ID \
  --strategy aws-sts-assume-role \
  --material role_arn="arn:aws:iam::${ACCOUNT}:role/openshell-sts-test-role" \
  --material session_name="openshell-sandbox" \
  --material aws_region="us-east-1"

# Mint the first set of credentials
openshell provider refresh rotate s3-test \
  --credential-key AWS_ACCESS_KEY_ID

# Verify
openshell provider refresh status s3-test
```

The status should show `refreshed` with an expiry ~1 hour from now.

## 5. Test S3 access from a sandbox

```shell
openshell sandbox create --name s3-smoke \
  --provider s3-test \
  -- bash -c '
BUCKET="<your-bucket-name>"
REGION="us-east-1"
CA=/etc/openshell-tls/ca-bundle.pem

echo "=== Upload ==="
curl -s --cacert $CA -X PUT -H "Content-Type: text/plain" \
  -d "hello from openshell sandbox via STS" \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/from-sandbox.txt" \
  -w "\nHTTP %{http_code}\n"

echo ""
echo "=== List ==="
curl -s --cacert $CA \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/?list-type=2&max-keys=5" \
  -w "\nHTTP %{http_code}\n"

echo ""
echo "=== Download ==="
curl -s --cacert $CA \
  "https://${BUCKET}.s3.${REGION}.amazonaws.com/from-sandbox.txt" \
  -w "\nHTTP %{http_code}\n"
'
```

All three operations should return `HTTP 200`. The download should print
`hello from openshell sandbox via STS`.

### What's happening

1. The gateway called `sts:AssumeRole` and stored three short-lived credentials
   (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) in the
   provider record.
2. The sandbox received placeholder values for these credentials as environment
   variables.
3. Curl sent unsigned HTTP requests through the sandbox proxy's CONNECT tunnel.
4. The proxy terminated TLS, stripped any existing AWS auth headers, resolved
   the real credentials from the `SecretResolver`, computed a fresh SigV4
   signature using the `aws-sigv4` crate, and forwarded the signed request to
   S3.
5. S3 validated the signature and accepted the request.

The sandbox never saw real AWS credentials — only placeholders.

### Using `--cacert`

The proxy terminates TLS and presents a certificate signed by the OpenShell
Sandbox CA. Curl needs `--cacert /etc/openshell-tls/ca-bundle.pem` to trust
it. Python clients (boto3, requests) need `AWS_CA_BUNDLE` or
`REQUESTS_CA_BUNDLE` set to the same path.

### Known limitation: chunked transfer encoding

S3 clients that use `Transfer-Encoding: chunked` (e.g., boto3 `put_object`)
will fail because the SigV4 relay buffers the body by `Content-Length` only.
Curl uses `Content-Length` by default and works. This will be addressed in a
follow-up.

## 6. Clean up

```shell
# Delete the sandbox
openshell sandbox delete s3-smoke

# Delete AWS resources
aws s3 rb "s3://${BUCKET}" --force
aws iam delete-role-policy --role-name openshell-sts-test-role --policy-name s3-access
aws iam delete-role --role-name openshell-sts-test-role
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `STS AssumeRole failed: dispatch failure` | Gateway doesn't have AWS credentials | Export credentials before starting: `eval "$(aws configure export-credentials --format env)"` |
| `Policy discovery sync failed: invalid wire type` | Supervisor image doesn't have updated proto | Rebuild: `CONTAINER_ENGINE=podman IMAGE_TAG=dev mise run build:docker:supervisor` |
| `CONNECT ... not permitted by policy` | Binary not in profile's `binaries` list | Use curl (in the list) or add your binary path to the policy |
| `AuthorizationHeaderMalformed: region 's3' is wrong` | Old `extract_aws_region` bug | Rebuild from latest branch (fixed in `d46749fc`) |
| `403 AccessDenied` from S3 | IAM role missing permissions, or STS creds expired | Check `openshell provider refresh status`; re-rotate if expired |
| `SSLEOFError` from boto3 | boto3 uses chunked encoding; SigV4 relay doesn't handle it yet | Use curl instead of boto3 for now |
| Supervisor uses wrong image | `supervisor_image` in wrong TOML section | Place under `[openshell.gateway]`, not `[openshell.gateway.gateway_jwt]` |
