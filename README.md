# bedrock-analysis-dga-domain.md


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
