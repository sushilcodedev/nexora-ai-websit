# NEXORA — Client Authorization & Scope Form

> Do not begin any technical check until this form is completed and signed by a person authorized to approve the work. This form is a practical record, not legal advice. The client should obtain their own legal review where appropriate.

## 1. Client and authorized representative
- Legal/business name:
- Representative name and role:
- Business email / phone:
- Website owner or authorized operator:
- Basis of authority (owner / employee with delegated authority / written third-party authorization):
- Supporting authorization reference (do not attach passwords or secrets):

## 2. Exact approved target
- Exact website URL to be checked:
- Exact hostname:
- Approved date and time window, including timezone:
- Approved source location (if relevant):
- Explicitly excluded hostnames, subdomains, paths, services, and third-party providers:

No wildcard scope. No additional hosts may be inferred from links, DNS, redirects, or discovered assets.

## 3. Permitted activity
The client authorizes only this limited activity:
- One HTTP HEAD request to the exact approved URL.
- Review of the response status and selected HTTP response headers.
- Preparation of a written hygiene report describing observations and limitations.

No GET crawling, scanning, exploitation, fuzzing, brute force, authentication attempts, data access, load testing, or production changes are authorized.

## 4. Impact and operating limits
- Maximum requests: 1 HEAD request to the exact URL.
- Timeout: up to 5 seconds.
- Redirects: not followed.
- Stop conditions: unexpected response, instability, client request, or any uncertainty about scope.
- Client emergency contact:

## 5. Data handling
- Evidence collected: response status and selected response headers only.
- Secrets, cookies, authorization headers, personal data, and unrelated data must not be collected or included in the report.
- Delivery method:
- Named recipient:
- Agreed deletion date for local working copies:

## 6. Service limitations
The client understands this is a limited, non-intrusive HTTP header hygiene review. It is not a penetration test, comprehensive vulnerability assessment, compliance audit, certification, or guarantee that the website is secure. A missing header is not by itself proof of an exploitable vulnerability. The client remains responsible for reviewing recommendations and authorizing any changes.

## 7. Fee and deliverable
- Agreed fee and currency:
- Deliverable: concise report of observed headers, explanations, recommendations, and limitations.
- Expected delivery date:
- Refund/cancellation terms agreed separately:

## 8. Authorization declaration
I confirm that I am authorized to approve the exact activity and targets listed above. I have reviewed the permitted actions, exclusions, request limit, and stop conditions. I understand no other system or activity is included.

- Authorized representative name:
- Role:
- Signature / approved electronic confirmation:
- Date and timezone:

**NEXORA reviewer:**  
- Name:
- Date:
- Scope rechecked immediately before test: Yes / No
