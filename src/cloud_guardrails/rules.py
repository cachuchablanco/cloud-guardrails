"""CIS-mapped checks over parsed Terraform resources.

Each rule emits fail / warn / pass findings. Rules inspect local HCL only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from cloud_guardrails.models import (
    Finding,
    Resource,
    as_bool,
    as_str,
    as_str_list,
    excerpt,
    line_of,
    looks_like_ref,
)
from cloud_guardrails.policy import (
    actions_of,
    is_allow,
    is_star_admin,
    parse_policy,
    principal_is_public,
    statements,
)

WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
SENSITIVE_PORTS = frozenset({22, 3389, 3306, 5432, 6379, 27017, 1433, 9200})
PUBLIC_ACLS = frozenset(
    {"public-read", "public-read-write", "authenticated-read", "website"}
)
ADMIN_POLICY_MARKERS = ("AdministratorAccess", "IAMFullAccess")
SENSITIVE_ATTRS = frozenset(
    {
        "password",
        "master_password",
        "secret",
        "secret_key",
        "access_key",
        "aws_secret_access_key",
        "aws_access_key_id",
        "api_key",
        "token",
        "private_key",
        "shared_secret",
        "db_password",
    }
)
PAB_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


@dataclass
class Inventory:
    resources: list[Resource]

    def of_type(self, *types: str) -> list[Resource]:
        want = set(types)
        return [r for r in self.resources if r.kind == "resource" and r.type in want]

    def data_of_type(self, *types: str) -> list[Resource]:
        want = set(types)
        return [r for r in self.resources if r.kind == "data" and r.type in want]

    def providers(self) -> list[Resource]:
        return [r for r in self.resources if r.kind == "provider"]

    def variables(self) -> list[Resource]:
        return [r for r in self.resources if r.kind == "variable"]


class Rule:
    id: str
    title: str
    cis: str

    def check(self, inv: Inventory) -> list[Finding]:
        raise NotImplementedError

    pass_title: str | None = None

    def emit(
        self,
        resource: Resource,
        severity: str,
        evidence: str,
        remediation: str,
        *,
        title: str | None = None,
        line: int | None = None,
        file_display: str | None = None,
    ) -> Finding:
        if title is None:
            title = self.pass_title if severity == "pass" and self.pass_title else self.title
        return Finding(
            rule_id=self.id,
            title=title,
            severity=severity,  # type: ignore[arg-type]
            cis=self.cis,
            file=file_display or _display_path(resource),
            line=line if line is not None else line_of(resource, evidence),
            resource=resource.address,
            evidence=excerpt(evidence),
            remediation=remediation,
        )


def _display_path(resource: Resource) -> str:
    try:
        from pathlib import Path

        return str(resource.file.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(resource.file)


def _refers_to(value: object, target: Resource) -> bool:
    blob = as_str(value) or str(value or "")
    if not blob:
        return False
    if target.address in blob:
        return True
    if target.kind == "resource" and f"{target.type}.{target.name}" in blob:
        return True
    bucket = as_str(target.attr("bucket") or target.attr("id"))
    if bucket and bucket in blob:
        return True
    return False


def _related(inv: Inventory, types: Sequence[str], target: Resource, attr: str = "bucket") -> list[Resource]:
    found: list[Resource] = []
    for res in inv.of_type(*types):
        if _refers_to(res.attr(attr), target):
            found.append(res)
            continue
        if attr != "bucket" and _refers_to(res.attr("bucket"), target):
            found.append(res)
    return found


# ---------------------------------------------------------------------------
# CG-S3-001  Public storage
# ---------------------------------------------------------------------------


class PublicStorageRule(Rule):
    id = "CG-S3-001"
    title = "Public S3 storage"
    pass_title = "S3 public access blocked"
    cis = "CIS AWS Foundations 2.1.4"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        buckets = inv.of_type("aws_s3_bucket")
        if not buckets:
            return findings
        for bucket in buckets:
            findings.append(self._check_bucket(inv, bucket))
        return findings

    def _check_bucket(self, inv: Inventory, bucket: Resource) -> Finding:
        reasons: list[str] = []
        acl = as_str(bucket.attr("acl"))
        if acl and acl in PUBLIC_ACLS:
            reasons.append(f'acl = "{acl}"')
        for acl_res in _related(inv, ("aws_s3_bucket_acl",), bucket, "bucket"):
            acl_val = as_str(acl_res.attr("acl"))
            if acl_val and acl_val in PUBLIC_ACLS:
                reasons.append(f'{acl_res.address} acl = "{acl_val}"')
            raw = acl_res.raw.lower()
            if "allusers" in raw or "authenticatedusers" in raw:
                reasons.append(f"{acl_res.address} grants to AllUsers/AuthenticatedUsers")

        for pol in _related(inv, ("aws_s3_bucket_policy",), bucket, "bucket"):
            policy = parse_policy(pol.attr("policy"))
            for stmt in statements(policy):
                if is_allow(stmt) and principal_is_public(stmt):
                    acts = ", ".join(actions_of(stmt)[:4]) or "*"
                    reasons.append(f"{pol.address} allows Principal=* Action={acts}")
                    break
            else:
                if policy is None and pol.attr("policy"):
                    blob = as_str(pol.attr("policy")) or pol.raw
                    if '"Principal"' in blob and '"*"' in blob and "Allow" in blob:
                        reasons.append(f"{pol.address} appears to allow Principal=*")

        pabs = _related(inv, ("aws_s3_bucket_public_access_block",), bucket, "bucket")
        if not pabs:
            reasons.append("missing aws_s3_bucket_public_access_block")
        else:
            for pab in pabs:
                unset = [flag for flag in PAB_FLAGS if as_bool(pab.attr(flag)) is not True]
                if unset:
                    reasons.append(
                        f"{pab.address} does not set {', '.join(unset)} = true"
                    )

        if reasons:
            return self.emit(
                bucket,
                "fail",
                "; ".join(reasons),
                "Add aws_s3_bucket_public_access_block (all four flags true), drop public ACLs, and avoid Principal=* bucket policies.",
            )
        return self.emit(
            bucket,
            "pass",
            "private ACL, no public policy, block-public-access enabled",
            "Keep all four public-access-block flags true; never attach a Principal=* policy.",
        )


# ---------------------------------------------------------------------------
# CG-SG-001  World-open security groups
# ---------------------------------------------------------------------------


class OpenSecurityGroupRule(Rule):
    id = "CG-SG-001"
    title = "Security group 0.0.0.0/0 on sensitive ports"
    pass_title = "No world-open admin ports"
    cis = "CIS AWS Foundations 5.2 / 5.3"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        groups = inv.of_type("aws_security_group")
        rules = inv.of_type("aws_security_group_rule")
        if not groups and not rules:
            return findings

        for sg in groups:
            hits = [_describe_ingress(block) for block in sg.nested("ingress")]
            hits = [h for h in hits if h]
            findings.extend(self._from_hits(sg, hits))

        by_sg: dict[str, list[tuple[Resource, str, str]]] = {}
        for rule in rules:
            if (as_str(rule.attr("type")) or "ingress") != "ingress":
                continue
            hit = _describe_ingress(rule.body)
            if not hit:
                continue
            key = as_str(rule.attr("security_group_id")) or rule.address
            by_sg.setdefault(key, []).append((rule, hit))
        for items in by_sg.values():
            resource = items[0][0]
            hits = [hit for _, hit in items]
            findings.extend(self._from_hits(resource, hits))
        return findings

    def _from_hits(self, resource: Resource, hits: list[tuple[str, str, int]]) -> list[Finding]:
        if not hits:
            return [
                self.emit(
                    resource,
                    "pass",
                    "no ingress from 0.0.0.0/0 or ::/0",
                    "Keep admin ports limited to known CIDRs (VPN/bastion), not the internet.",
                )
            ]
        out: list[Finding] = []
        for severity, evidence, from_port in hits:
            rem = (
                "Replace 0.0.0.0/0 with a bastion/VPN CIDR; never expose 22/3389 or all-ports to the world."
                if severity == "fail"
                else "World-open non-admin ports should still sit behind a load balancer or WAF, not the instance SG."
            )
            title = self.title if severity == "fail" else "Security group 0.0.0.0/0 on a non-admin port"
            out.append(
                self.emit(
                    resource,
                    severity,
                    evidence,
                    rem,
                    title=title,
                    line=_line_containing(resource, "from_port", str(from_port)),
                )
            )
        return out


def _describe_ingress(block: dict) -> tuple[str, str, int] | None:
    cidrs = set(as_str_list(block.get("cidr_blocks")) + as_str_list(block.get("ipv6_cidr_blocks")))
    world = sorted(cidrs & WORLD_CIDRS)
    if not world:
        return None
    protocol = (as_str(block.get("protocol")) or "tcp").lower()
    from_port = _port(block.get("from_port"), default=0)
    to_port = _port(block.get("to_port"), default=from_port)
    world_s = ", ".join(world)
    all_ports = protocol in {"-1", "all"} or (from_port == 0 and to_port in {0, 65535})
    if all_ports:
        return "fail", f"ingress protocol={protocol} ports={from_port}-{to_port} cidr={world_s} (all traffic)", from_port
    overlap = [p for p in sorted(SENSITIVE_PORTS) if from_port <= p <= to_port]
    if overlap:
        return "fail", f"ingress protocol={protocol} ports={from_port}-{to_port} cidr={world_s} (sensitive {overlap})", from_port
    return "warn", f"ingress protocol={protocol} ports={from_port}-{to_port} cidr={world_s}", from_port


def _line_containing(resource: Resource, key: str, port: str) -> int:
    import re as _re
    pat = _re.compile(rf"{_re.escape(key)}\s*=\s*{_re.escape(port)}\b")
    for offset, line in enumerate(resource.raw.splitlines()):
        if pat.search(line):
            return resource.line + offset
    return resource.line


def _port(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    text = as_str(value)
    if text and text.lstrip("-").isdigit():
        return int(text)
    return default


# ---------------------------------------------------------------------------
# CG-ENC-001  Encryption
# ---------------------------------------------------------------------------


class EncryptionRule(Rule):
    id = "CG-ENC-001"
    title = "Unencrypted storage"
    pass_title = "Storage encryption enabled"
    cis = "CIS AWS Foundations 2.1.1 / 2.2.1 / 2.3.1"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._s3(inv))
        findings.extend(self._ebs(inv))
        findings.extend(self._instances(inv))
        findings.extend(self._rds(inv))
        return findings

    def _s3(self, inv: Inventory) -> list[Finding]:
        out: list[Finding] = []
        for bucket in inv.of_type("aws_s3_bucket"):
            inline = bucket.nested("server_side_encryption_configuration")
            related = _related(
                inv, ("aws_s3_bucket_server_side_encryption_configuration",), bucket, "bucket"
            )
            if inline or related:
                out.append(
                    self.emit(
                        bucket,
                        "pass",
                        "server-side encryption configured",
                        "Keep SSE-S3 or SSE-KMS enabled; prefer a customer-managed KMS key for sensitive data.",
                    )
                )
            else:
                out.append(
                    self.emit(
                        bucket,
                        "fail",
                        "no server_side_encryption_configuration",
                        "Add aws_s3_bucket_server_side_encryption_configuration with SSE-KMS or AES256.",
                    )
                )
        return out

    def _ebs(self, inv: Inventory) -> list[Finding]:
        out: list[Finding] = []
        for vol in inv.of_type("aws_ebs_volume"):
            flag = as_bool(vol.attr("encrypted"))
            if flag is True:
                out.append(
                    self.emit(
                        vol,
                        "pass",
                        "encrypted = true",
                        "Keep EBS encryption on and specify kms_key_id for regulated data.",
                    )
                )
            else:
                ev = "encrypted = false" if flag is False else "encrypted not set (defaults to false unless account default is on)"
                out.append(
                    self.emit(
                        vol,
                        "fail",
                        ev,
                        "Set encrypted = true on aws_ebs_volume (and a kms_key_id).",
                    )
                )
        return out

    def _instances(self, inv: Inventory) -> list[Finding]:
        out: list[Finding] = []
        for inst in inv.of_type("aws_instance"):
            roots = inst.nested("root_block_device")
            ebs = inst.nested("ebs_block_device")
            if not roots and not ebs:
                out.append(
                    self.emit(
                        inst,
                        "warn",
                        "no root_block_device encryption set",
                        "Set root_block_device { encrypted = true } (AMI default may be unencrypted).",
                    )
                )
                continue
            bad = False
            for block in roots + ebs:
                if as_bool(block.get("encrypted")) is True:
                    continue
                bad = True
                which = "root_block_device" if block in roots else "ebs_block_device"
                out.append(
                    self.emit(
                        inst,
                        "fail",
                        f"{which} encrypted is not true",
                        "Set encrypted = true on root_block_device / ebs_block_device.",
                    )
                )
            if not bad:
                out.append(
                    self.emit(
                        inst,
                        "pass",
                        "instance block devices encrypted",
                        "Keep encrypted = true on every attached volume.",
                    )
                )
        return out

    def _rds(self, inv: Inventory) -> list[Finding]:
        out: list[Finding] = []
        for db in inv.of_type("aws_db_instance"):
            flag = as_bool(db.attr("storage_encrypted"))
            if flag is True:
                out.append(
                    self.emit(
                        db,
                        "pass",
                        "storage_encrypted = true",
                        "Keep storage_encrypted = true and pass kms_key_id.",
                    )
                )
            else:
                ev = "storage_encrypted = false" if flag is False else "storage_encrypted not set"
                out.append(
                    self.emit(
                        db,
                        "fail",
                        ev,
                        "Set storage_encrypted = true on aws_db_instance.",
                    )
                )
        return out


# ---------------------------------------------------------------------------
# CG-IAM-001  Overly-admin IAM
# ---------------------------------------------------------------------------


class IamAdminRule(Rule):
    id = "CG-IAM-001"
    title = "IAM policy grants full admin (*:*)"
    pass_title = "IAM policy is not wildcard admin"
    cis = "CIS AWS Foundations 1.16"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        policy_types = (
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
        )
        saw_policy = False
        for res in inv.of_type(*policy_types):
            saw_policy = True
            findings.extend(self._policy_resource(res))
        for res in inv.data_of_type("aws_iam_policy_document"):
            saw_policy = True
            findings.extend(self._policy_document(res))
        for res in inv.of_type(
            "aws_iam_role_policy_attachment",
            "aws_iam_policy_attachment",
            "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment",
        ):
            arn = as_str(res.attr("policy_arn")) or ""
            if any(marker in arn for marker in ADMIN_POLICY_MARKERS):
                findings.append(
                    self.emit(
                        res,
                        "fail",
                        f"policy_arn = {arn}",
                        "Detach AdministratorAccess; attach a job-function policy scoped to the role's tasks.",
                    )
                )
            # Custom policy ARNs are judged on the policy document itself, not the attachment.
        if not saw_policy and not findings:
            return findings
        return findings

    def _policy_resource(self, res: Resource) -> list[Finding]:
        policy = parse_policy(res.attr("policy"))
        return self._from_statements(res, statements(policy), raw=as_str(res.attr("policy")) or res.raw)

    def _policy_document(self, res: Resource) -> list[Finding]:
        stmts: list[dict] = []
        for block in res.nested("statement"):
            stmts.append(
                {
                    "Effect": block.get("effect") or block.get("Effect") or "Allow",
                    "Action": block.get("actions") or block.get("action"),
                    "Resource": block.get("resources") or block.get("resource"),
                }
            )
        return self._from_statements(res, stmts, raw=res.raw)

    def _from_statements(self, res: Resource, stmts: list[dict], raw: str) -> list[Finding]:
        for stmt in stmts:
            if is_star_admin(stmt):
                return [
                    self.emit(
                        res,
                        "fail",
                        'Statement Allow Action="*" Resource="*"',
                        'Replace Action="*" Resource="*" with the specific API calls and ARNs the role needs.',
                    )
                ]
        # fallback: raw text
        if '"Action"' in raw and '"*"' in raw and '"Resource"' in raw:
            # only fail if both appear as star — cheap extra net
            if _raw_star_star(raw):
                return [
                    self.emit(
                        res,
                        "fail",
                        'policy document contains Action "*" and Resource "*"',
                        'Replace Action="*" Resource="*" with scoped actions and ARNs.',
                    )
                ]
        return [
            self.emit(
                res,
                "pass",
                "no Allow *:* statement",
                "Keep reviewing new statements so a wildcard admin grant does not sneak back in.",
            )
        ]


def _raw_star_star(raw: str) -> bool:
    compact = raw.replace(" ", "")
    return ('"Action":"*"' in compact or "Action=*" in compact or 'Action="*"' in compact) and (
        '"Resource":"*"' in compact or "Resource=*" in compact or 'Resource="*"' in compact
    )


# ---------------------------------------------------------------------------
# CG-VPC-001  Flow logs
# ---------------------------------------------------------------------------


class VpcFlowLogRule(Rule):
    id = "CG-VPC-001"
    title = "VPC without flow logs"
    pass_title = "VPC flow logs enabled"
    cis = "CIS AWS Foundations 3.7"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        vpcs = inv.of_type("aws_vpc")
        logs = inv.of_type("aws_flow_log")
        for vpc in vpcs:
            matched = [fl for fl in logs if _refers_to(fl.attr("vpc_id"), vpc)]
            if matched:
                findings.append(
                    self.emit(
                        vpc,
                        "pass",
                        f"flow log {matched[0].address}",
                        "Keep vpc_id-level flow logs enabled and retained in CloudWatch/S3.",
                    )
                )
            else:
                findings.append(
                    self.emit(
                        vpc,
                        "fail",
                        "no aws_flow_log with this vpc_id",
                        "Add aws_flow_log (traffic_type = ALL) pointing at this VPC.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# CG-RDS-001  Public RDS
# ---------------------------------------------------------------------------


class PublicRdsRule(Rule):
    id = "CG-RDS-001"
    title = "Publicly accessible RDS instance"
    pass_title = "RDS is not publicly accessible"
    cis = "AWS FSBP RDS.2 (CIS-adjacent)"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for db in inv.of_type("aws_db_instance"):
            flag = as_bool(db.attr("publicly_accessible"))
            if flag is True:
                findings.append(
                    self.emit(
                        db,
                        "fail",
                        "publicly_accessible = true",
                        "Set publicly_accessible = false and reach the DB via a private subnet / bastion.",
                    )
                )
            elif flag is False:
                findings.append(
                    self.emit(
                        db,
                        "pass",
                        "publicly_accessible = false",
                        "Keep the instance in private subnets with SG ingress only from the app tier.",
                    )
                )
            else:
                findings.append(
                    self.emit(
                        db,
                        "warn",
                        "publicly_accessible not set (AWS default is false — set it explicitly)",
                        "Set publicly_accessible = false explicitly so a later change is reviewable.",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# CG-EC2-001  IMDSv2
# ---------------------------------------------------------------------------


class ImdsRule(Rule):
    id = "CG-EC2-001"
    title = "IMDSv2 (http_tokens) not required"
    pass_title = "IMDSv2 required"
    cis = "CIS AWS Foundations 5.6"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        for res in inv.of_type("aws_instance", "aws_launch_template"):
            blocks = res.nested("metadata_options")
            if res.type == "aws_launch_template":
                for nested in res.nested("launch_template_data") or [{}]:
                    extra = nested.get("metadata_options") if isinstance(nested, dict) else None
                    if extra:
                        blocks = extra if isinstance(extra, list) else [extra]
            if not blocks:
                findings.append(
                    self.emit(
                        res,
                        "fail",
                        "metadata_options missing (IMDSv1 remains available)",
                        'Set metadata_options { http_tokens = "required" } so only IMDSv2 is accepted.',
                    )
                )
                continue
            tokens = as_str(blocks[0].get("http_tokens")) if blocks else None
            if tokens == "required":
                findings.append(
                    self.emit(
                        res,
                        "pass",
                        'http_tokens = "required"',
                        "Keep IMDSv2 required; consider hop limit 1.",
                    )
                )
            else:
                findings.append(
                    self.emit(
                        res,
                        "fail",
                        f'http_tokens = "{tokens or "optional"}"',
                        'Set metadata_options { http_tokens = "required" } (IMDSv2).',
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# CG-SEC-001  Hardcoded secrets
# ---------------------------------------------------------------------------


class HardcodedSecretRule(Rule):
    id = "CG-SEC-001"
    title = "Hardcoded secret in Terraform"
    cis = "CWE-798 / CIS 1.14-adjacent"

    def check(self, inv: Inventory) -> list[Finding]:
        findings: list[Finding] = []
        targets = [
            r
            for r in inv.resources
            if r.kind in {"resource", "provider", "variable"}
        ]
        any_hit = False
        for res in targets:
            hits = list(_secret_hits(res))
            if not hits:
                continue
            any_hit = True
            for attr, value in hits:
                findings.append(
                    self.emit(
                        res,
                        "fail",
                        f'{attr} = "{_redact(value)}"',
                        "Move the value to a tfvars-ignored file, SSM/Secrets Manager, or a CI secret; never commit it.",
                        title=f"Hardcoded {attr}",
                    )
                )
        return findings


def _secret_hits(res: Resource) -> Iterable[tuple[str, str]]:
    if res.kind == "variable":
        name = res.name.lower()
        default = res.attr("default")
        if default is None or looks_like_ref(default) or as_bool(default) is not None:
            return
        if any(tok in name for tok in ("password", "secret", "token", "key", "credential")):
            text = as_str(default)
            if text:
                yield "default", text
        return
    body = dict(res.body)
    # provider access_key / secret_key
    for key, value in body.items():
        if key.lower() not in SENSITIVE_ATTRS:
            continue
        if looks_like_ref(value):
            continue
        if as_bool(value) is not None:
            continue
        text = as_str(value)
        if not text:
            continue
        if text in {"", "null"}:
            continue
        yield key, text


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]


ALL_RULES: list[Rule] = [
    PublicStorageRule(),
    OpenSecurityGroupRule(),
    EncryptionRule(),
    IamAdminRule(),
    VpcFlowLogRule(),
    PublicRdsRule(),
    ImdsRule(),
    HardcodedSecretRule(),
]
