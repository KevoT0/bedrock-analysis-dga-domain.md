# bedrock-analysis-dga-domain.md


===

System Prompt: 
You are a senior AWS Cloud Security Architect specializing in IAM and incident response. Always prioritize least-privilege principles, AWS-native tools (Access Analyzer, IMDSv2, SCPs, CloudTrail), and MITRE ATT&CK alignment in your recommendations. Responses must be structured, concise, and free of hallucination.

===

===

You are a senior AWS IAM & Cloud Security Engineer analyzing GuardDuty findings.

Here is the raw GuardDuty finding attached (11.png)

Analyze it step-by-step and respond ONLY in this exact structured format:

Attack Chain Summary (plain English, 3–5 sentences)
Risk Level (1–10) + one-sentence explanation
Immediate IAM Remediations (numbered list, 3–5 items – focus on least privilege, credential hygiene, Access Analyzer, etc.)
Next Investigation Steps (numbered list, 2–4 items)
Be concise, actionable, and professional. No extra chit-chat.

===

# GuardDuty Finding Analysis: Trojan:Runtime/DGADomainRequest.CIDNS

---

## 1. Attack Chain Summary

A process running inside a container (Resource ID: `GeneratedFindingContainerName`) on EC2 instance `i-99999999` in account `006361131895` (us-east-1) is actively querying **Domain Generation Algorithm (DGA) domains** — a hallmark of malware command-and-control (C2) communication. This strongly indicates the container workload has been compromised, likely through a vulnerable application, exposed service, or tainted container image. The malware is attempting to reach its C2 infrastructure using algorithmically generated domains to evade static blocklists. If successful, the attacker could exfiltrate data, receive further instructions, or pivot laterally within the AWS environment using any IAM credentials available to the instance/container.

---

## 2. Risk Level: **9/10**

Active DGA-based C2 communication from a runtime container indicates a confirmed compromise with immediate risk of data exfiltration, lateral movement, and credential theft via the instance's IAM role or container role.

---

## 3. Immediate IAM Remediations

1. **Identify and temporarily revoke active IAM role sessions** for the EC2 instance profile and any EKS/ECS task roles attached to the compromised container by adding an inline deny-all policy with a `aws:TokenIssueTime` condition predating the compromise (02-21-2026 23:49 UTC).
2. **Rotate all credentials and secrets** accessible to the instance/container — including IAM role temporary credentials, any secrets in environment variables, and any Secrets Manager or Parameter Store values the role has access to.
3. **Scope down the instance/task IAM role** using IAM Access Analyzer to validate that the role follows least privilege; remove any overly broad permissions (e.g., `s3:*`, `sts:AssumeRole`, `iam:*`) that could enable lateral movement.
4. **Enable IMDSv2 (hop limit = 1)** on the EC2 instance to prevent potential SSRF-based credential theft from the instance metadata service, and restrict container access to the instance role where not needed.
5. **Audit CloudTrail for any API calls** made by the compromised role's temporary credentials between the finding time and now to determine if the attacker has already used stolen credentials for privilege escalation or data access.

---

## 4. Next Investigation Steps

1. **Isolate the container and host immediately** — stop the compromised container, move the EC2 instance to a quarantine security group (ingress/egress denied), and capture a memory dump and disk snapshot for forensic analysis before termination.
2. **Analyze the container image and runtime process** — identify `GeneratedFindingProcessName`, trace it to its container image, check the image for known vulnerabilities (ECR scanning), and determine the initial access vector (e.g., supply chain compromise, exposed service, RCE vulnerability).
3. **Query VPC Flow Logs and DNS logs (Route 53 Resolver)** to identify the specific DGA domains queried, any successful external connections, and data transfer volumes that could indicate exfiltration.
4. **Use Amazon Detective** (as suggested in the finding) to map the full blast radius — correlate related findings, identify any other compromised resources in the account, and trace lateral movement attempts across the environment.


===

Note: "First Bedrock inference on GuardDuty Trojan:Runtime/DGADomainRequest.CIDNS sample – High-severity malware C2 detection. Generated structured analysis & IAM remediations."



=============================================================================================================
==========================


Name: bedrock-analysis-iam-compromised-credentials.md


## Prompt: 

You are a senior AWS IAM & Cloud Security Engineer analyzing GuardDuty findings.

Here is the raw GuardDuty finding attached 12.png

Analyze it step-by-step and respond ONLY in this exact structured format:

Attack Chain Summary (plain English, 3–5 sentences)
Risk Level (1–10) + one-sentence explanation
Immediate IAM Remediations (numbered list, 3–5 items – focus on least privilege, credential hygiene, Access Analyzer, etc.)
Next Investigation Steps (numbered list, 2–4 items)
Be concise, actionable, and professional. No extra chit-chat. You are a senior AWS Cloud Security Architect specializing in IAM and incident response. Always prioritize least-privilege principles, AWS-native tools (Access Analyzer, IMDSv2, SCPs, CloudTrail), and MITRE ATT&CK alignment in your recommendations. Responses must be structured, concise, and free of hallucination.


# GuardDuty Finding Analysis: AttackSequence:IAM/CompromisedCredentials

---

## 1. Attack Chain Summary

IAM user `john_doe` (principal ID `AIDA3UBBJ2K3TVEXAMPLE`) in account `111122223333` has been **critically compromised**, with the attacker connecting from a **known Tor exit node (10.0.0.1)** to anonymize their origin. The adversary executed a deliberate multi-stage attack: they first performed **discovery** (`iam:ListUsers` — MITRE T1087.004) to enumerate the account, then **escalated privileges** by calling `iam:CreateRole` and `iam:AttachRolePolicy` (MITRE T1098.003 — creating backdoor roles with elevated permissions for persistence). Critically, the attacker then attempted **defense evasion** by calling `cloudtrail:DeleteTrail` (MITRE T1562.008) to blind the organization's logging and cover their tracks. This is a textbook credential compromise attack chain spanning 5 MITRE ATT&CK tactics (Initial Access → Discovery → Privilege Escalation → Persistence → Defense Evasion), indicating a sophisticated and deliberate adversary — not opportunistic scanning.

---

## 2. Risk Level: **10/10**

This is a confirmed active compromise with privilege escalation, persistence mechanism creation, and deliberate audit log destruction from an anonymized (Tor) source — representing maximum risk to the account and potentially the entire AWS Organization.

---

## 3. Immediate IAM Remediations

1. **Disable all access keys and console password for `john_doe` immediately** — deactivate (do not delete yet, for forensics) all access keys via `aws iam update-access-key --status Inactive` and disable console access; simultaneously revoke all active sessions by attaching an inline deny-all policy with `aws:TokenIssueTime` condition set before the current time.

2. **Identify and delete/disable all attacker-created IAM roles** — audit CloudTrail for every `iam:CreateRole` and `iam:AttachRolePolicy` call made by `john_doe` during the compromise window; quarantine these roles immediately with explicit deny policies, then delete after forensic capture. Pay special attention to roles with `AdministratorAccess`, `iam:*`, or `sts:AssumeRole` trust policies pointing to external accounts.

3. **Restore CloudTrail immediately** — verify all trails across all regions; if `cloudtrail:DeleteTrail` succeeded, recreate the trail with identical configuration, enable log file validation, enforce an SCP at the OU level to deny `cloudtrail:DeleteTrail` and `cloudtrail:StopLogging` for all non-breakglass principals going forward.

4. **Run IAM Access Analyzer** on the entire account to detect any externally shared resources, cross-account role trusts, or policy grants the attacker may have introduced during the privilege escalation phase; also run Access Analyzer for unused access to identify and scope down `john_doe`'s original permissions that enabled this chain.

5. **Deploy preventive SCPs immediately** at the Organization level:
   - Deny all API calls sourced from known anonymization networks (Tor) using `aws:SourceIp` condition keys.
   - Deny `iam:CreateRole`, `iam:AttachRolePolicy`, `cloudtrail:DeleteTrail`, and `cloudtrail:StopLogging` except from explicitly approved admin roles.

---

## 4. Next Investigation Steps

1. **Full CloudTrail forensic analysis** — query CloudTrail (and CloudTrail Lake if available) for ALL API calls by `john_doe`'s principal ID and any newly created roles/credentials during and after the compromise window; determine if `sts:AssumeRole` was called to pivot into other accounts, if S3 data was accessed/exfiltrated, or if additional persistence mechanisms (Lambda functions, EC2 key pairs, SSM documents) were created.

2. **Determine initial access vector** — investigate how `john_doe`'s credentials were compromised: check for long-lived access keys (age/rotation status), credential exposure in public repositories (GitHub, etc.), phishing logs, or prior GuardDuty findings; check if MFA was enabled and whether it was bypassed.

3. **Blast radius assessment across the Organization** — use Amazon Detective to map all related entities and behaviors; check if the attacker-created roles have trust policies allowing assumption from external accounts; query CloudTrail in all linked accounts for any cross-account activity from compromised credentials or newly created roles.

4. **Validate logging integrity** — confirm whether the `cloudtrail:DeleteTrail` call actually succeeded (check the CloudTrail event for `responseElements`); if it did, there may be a gap in visibility — cross-reference VPC Flow Logs, S3 access logs, and GuardDuty findings to reconstruct any activity during the logging blind spot.



NOTE: "Bedrock (Claude Opus 4.6) automated analysis of sample GuardDuty AttackSequence:IAM/CompromisedCredentials finding. Demonstrates AI-assisted triage, risk scoring, IAM remediations, and IR steps for credential compromise scenarios."


### AI-Powered GuardDuty Triage Prototype
Early prototype using Amazon Bedrock to analyze GuardDuty findings:
- DGA malware C2 detection → Risk 9/10 + container isolation & IMDSv2 fixes
- IAM credential compromise Attack Sequence → Risk 10/10 + session revocation, role deletion, SCPs, Access Analyzer
Goal: Automate summarization + remediation suggestions for Critical findings.
