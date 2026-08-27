# Fixtures

Two static Terraform trees. The scanner reads these files only — it never calls AWS.

| Tree | Intent |
|---|---|
| `insecure/` | Planted junior-interview misses. `cloud-guardrails scan` must exit 1. |
| `secure/` | The same resources hardened. Should produce **no FAIL**. |

Neither tree is meant to `terraform apply`. Names, AMI IDs, and account-looking strings are lab-only.

## Planted issues (`insecure/`)

| File | Rule | What is wrong |
|---|---|---|
| `main.tf` | CG-SEC-001 | `access_key` / `secret_key` literals on the AWS provider |
| `s3.tf` | CG-S3-001 | `acl = "public-read"`, Principal=`*` bucket policy, no public-access block (both buckets) |
| `s3.tf` | CG-ENC-001 | no `aws_s3_bucket_server_side_encryption_configuration` |
| `sg.tf` | CG-SG-001 | ingress 22, 3389, and protocol `-1` from `0.0.0.0/0` (HTTP/80 is WARN) |
| `iam.tf` | CG-IAM-001 | customer policy `Action="*" Resource="*"` plus `AdministratorAccess` attachment |
| `vpc.tf` | CG-VPC-001 | `aws_vpc.main` has no `aws_flow_log` |
| `rds.tf` | CG-RDS-001 | `publicly_accessible = true` |
| `rds.tf` | CG-ENC-001 | `storage_encrypted = false` |
| `rds.tf` | CG-SEC-001 | `password = "ChangeMeNow-LabOnly!"` |
| `ec2.tf` | CG-EC2-001 | `http_tokens = "optional"` (IMDSv1 still allowed) |
| `ec2.tf` | CG-ENC-001 | instance root volume and `aws_ebs_volume.data` unencrypted |

## What `secure/` changes

- Provider has a region only (no keys).
- S3: all four public-access-block flags, SSE-KMS, no public ACL/policy.
- SG: SSH from `10.20.0.0/16`; Postgres only from the app SG.
- IAM: `s3:GetObject`/`s3:ListBucket` on one bucket ARN.
- VPC: `aws_flow_log` with `traffic_type = ALL` to CloudWatch Logs.
- RDS: private, encrypted, `manage_master_user_password = true`.
- EC2: `http_tokens = "required"`, encrypted root + data volumes.

Passwords, keys, and ARNs here are synthetic. Do not treat them as real credentials.
