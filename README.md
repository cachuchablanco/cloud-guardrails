# Cloud Guardrails

A small **Terraform misconfiguration scanner**: parse in-repo `.tf` fixtures, run CIS-mapped checks, and print a **fail/warn/pass** table plus `out/findings.json`.

Built as a portfolio piece for junior cloud / cybersecurity roles. It demonstrates the misses that show up in every AWS interview — public S3, `0.0.0.0/0` on 22/3389, unencrypted volumes, `*:*` IAM — without needing AWS credentials.

Not a production CSPM. Local files only. It never calls cloud APIs.

## Why it exists

Cloud security interviews keep coming back to the same handful of Terraform mistakes. This repo packages those checks in a few hundred lines of Python a recruiter can clone, run, and read in about twenty minutes. `fixtures/insecure/` is the planted mess; `fixtures/secure/` is the same shape hardened.


## If you ask me on a call

I would run `cloud-guardrails scan fixtures/insecure` and read the table. Public S3, SSH open to the world, `*:*` IAM, unencrypted disks. Those are the questions cloud interviews actually ask.

What I would say next:

- This is not Checkov. Checkov exists. This is a readable subset so I can explain each check
- Local fixtures only. No AWS keys, no live account, no exploit
- Exit code 1 on FAIL is on purpose. You can drop it in CI. The insecure fixture is tested so CI does not go red for the planted mess
- If they ask why not tfsec: same answer. I wanted file:line evidence I wrote myself

If they open `rules.py`, I can walk S3 public access, security groups, and why IMDS `optional` is still a fail.


## Architecture

```
fixtures/**/*.tf  →  python-hcl2  →  Resource[]  →  rules  →  Finding[]
                                                      ↘ CLI table
                                                      ↘ out/findings.json
```

- **Parser** (`src/cloud_guardrails/parser.py`) loads HCL2 with `python-hcl2` and attaches file:line from the source text. No `terraform plan`, no state, no AWS SDK.
- **Rules** (`src/cloud_guardrails/rules.py`) are plain classes over that inventory. Each check emits fail / warn / pass with a CIS (or adjacent) mapping, evidence excerpt, and a one-line remediation.
- **CLI** (`cloud-guardrails scan`) writes JSON and exits **1** if any FAIL (usable as a CI gate). The planted insecure tree is asserted inside pytest so GitHub Actions does not treat that exit 1 as a red job.

## Checks

| Rule ID | What it catches | Mapping |
|---|---|---|
| CG-S3-001 | Public ACL, Principal=`*` bucket policy, missing/incomplete public-access block | CIS AWS 2.1.4 |
| CG-SG-001 | Ingress from `0.0.0.0/0` or `::/0` on 22, 3389, other admin ports, or all traffic (other world-open ports are WARN) | CIS AWS 5.2 / 5.3 |
| CG-ENC-001 | Unencrypted S3, EBS, instance volumes, RDS storage | CIS AWS 2.1.1 / 2.2.1 / 2.3.1 |
| CG-IAM-001 | `Action="*" Resource="*"` or `AdministratorAccess` | CIS AWS 1.16 |
| CG-VPC-001 | `aws_vpc` with no matching `aws_flow_log` | CIS AWS 3.7 |
| CG-RDS-001 | `publicly_accessible = true` | AWS FSBP RDS.2 |
| CG-EC2-001 | `http_tokens` missing or `optional` (IMDSv1 still allowed) | CIS AWS 5.6 |
| CG-SEC-001 | Literal `password` / `access_key` / `secret_key` in `.tf` | CWE-798 |

Planted issues are listed in [`fixtures/README.md`](fixtures/README.md).

## Quick start

Requires Python 3.11+.

```bash
cd cloud-guardrails
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
cloud-guardrails scan fixtures/insecure
```

(`python -m cloud_guardrails scan fixtures/insecure` works too.)

The insecure tree **must** exit 1. The secure tree should exit 0:

```bash
cloud-guardrails scan fixtures/secure
```

JSON lands at `out/findings.json` (severity, rule id, CIS mapping, `file:line`, resource address, evidence, remediation).

### Expected CLI output (abridged)

```text
Cloud Guardrails — scanning fixtures/insecure
  parsed  22 blocks  from 7 files

FAIL  (18)
  FAIL  CG-S3-001   aws_s3_bucket.public_logs
        Public S3 storage  [CIS AWS Foundations 2.1.4]
        fixtures/insecure/s3.tf:5
        acl = "public-read"; aws_s3_bucket_policy.public_logs allows Principal=* ...
        → Add aws_s3_bucket_public_access_block (all four flags true), drop public ACLs...
  FAIL  CG-SG-001   aws_security_group.app
        Security group 0.0.0.0/0 on sensitive ports  [CIS AWS Foundations 5.2 / 5.3]
        fixtures/insecure/sg.tf:8
        ingress protocol=tcp ports=22-22 cidr=0.0.0.0/0 (sensitive [22])
        → Replace 0.0.0.0/0 with a bastion/VPN CIDR...
  FAIL  CG-IAM-001  aws_iam_policy.full_admin
        IAM policy grants full admin (*:*)  [CIS AWS Foundations 1.16]
        fixtures/insecure/iam.tf:19
        Statement Allow Action="*" Resource="*"
  FAIL  CG-VPC-001  aws_vpc.main
        VPC without flow logs  [CIS AWS Foundations 3.7]
        fixtures/insecure/vpc.tf:2
        no aws_flow_log with this vpc_id
  FAIL  CG-RDS-001  aws_db_instance.app
        Publicly accessible RDS instance  [AWS FSBP RDS.2 (CIS-adjacent)]
        fixtures/insecure/rds.tf:19
        publicly_accessible = true
  FAIL  CG-EC2-001  aws_instance.web
        IMDSv2 (http_tokens) not required  [CIS AWS Foundations 5.6]
        fixtures/insecure/ec2.tf:12
        http_tokens = "optional"
  FAIL  CG-SEC-001  provider.aws
        Hardcoded access_key  [CWE-798 / CIS 1.14-adjacent]
        fixtures/insecure/main.tf:15
        access_key = "EX****AL"

WARN  (1)
  WARN  CG-SG-001   aws_security_group.app
        Security group 0.0.0.0/0 on a non-admin port
        fixtures/insecure/sg.tf:33
        ingress protocol=tcp ports=80-80 cidr=0.0.0.0/0

Summary  FAIL=18  WARN=1  PASS=0
Wrote 19 findings → out/findings.json
```

(Exact FAIL count is 18 today: two public buckets, several encryption hits, SSH+RDP+all-traffic, both IAM flavors, plus RDS/IMDS/secrets. All eight rule IDs must appear as FAIL.)

`fixtures/secure/` currently reports **FAIL=0  PASS=12**.

## What this is not

- Not a live AWS/GCP scanner. There are no credentials, no `Describe*` calls, no exploit payloads.
- Not a replacement for Checkov / tfsec / Prowler. Those tools exist; this repo is the readable subset.
- Fixtures are not `terraform apply`'d. AMI IDs and bucket names are lab-only.

## What I'd add next

- **Read-only live AWS** behind a dedicated IAM role (S3 public-access block, SG ingress, RDS public flag, IMDS on running instances) — same Finding model, different inventory source.
- **`terraform plan -json`** so planned values (including interpolations) are scanned, not just HCL literals.
- **SARIF** output for GitHub code scanning.
- GCP/Azure resource types using the same Rule interface.

## License

MIT. See [LICENSE](LICENSE).
