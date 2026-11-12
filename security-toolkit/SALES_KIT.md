# NEXORA AI — Website Security Hygiene Review
Version 1.0 · Service launch kit · Draft for owner review

## The first service to sell

**Service name:** NEXORA Website Security Hygiene Review

**Positioning:** A small, clearly scoped, non-intrusive review that helps a website owner understand a few basic HTTP security response headers and what to discuss with their developer.

This is not a penetration test, vulnerability assessment, compliance audit, certification, guarantee of security, or substitute for a qualified security professional.

## Who it is for
- Independent businesses and local service providers with a website.
- Creators, portfolio owners, and small organizations.
- Developers who want a beginner-friendly explanation of basic response-header observations.

Do not target high-risk systems, banks, hospitals, government services, payment systems, or production systems where even a single unexpected request could cause harm.

## Pilot pricing to validate demand
These are proposed introductory prices, not researched market averages or guaranteed earnings.

| Market | Pilot price | Deliverable |
|---|---:|---|
| India | ₹499 per website | One-page findings summary + recommendations |
| International | US$9 per website | Same deliverable, subject to a lawful payment method and clear written agreement |

Start with one website per client. Do not offer subscriptions or recurring scans yet. Quote only after reviewing the requested scope and confirming that the work is within your current skills.

## Exact work included in this MVP service
1. Confirm the client controls the website or has authority to commission the review.
2. Obtain signed written permission and exact hostname/URL, permitted date/time, and exclusions.
3. Confirm that the requested URL is within the written scope.
4. Run NEXORA's single HTTP HEAD request, which does not follow redirects, against the exact approved URL.
5. Record which of the following response-header observations are present: Content-Security-Policy, Strict-Transport-Security (HTTPS only), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and clickjacking-related headers.
6. Manually review the result, explain limitations, and prepare a concise report with practical recommendations.
7. Deliver the report securely to the client and delete working copies on the agreed date.

A missing header is a review item, not proof of an exploitable vulnerability. HEAD responses can differ from GET responses. Header presence alone does not prove the policy is correct or effective.

## Explicitly excluded
- Exploitation, proof-of-concept attacks, fuzzing, brute force, credential testing, or social engineering.
- Crawling, directory enumeration, port scanning, vulnerability scanning, or third-party scanner execution.
- Login to customer accounts, access to personal data, source-code review, infrastructure/cloud review, or payment-flow testing.
- Fixing code, changing DNS/server settings, or making production changes.
- Compliance certification, legal advice, guaranteed detection, or a claim that a site is "secure".
- Any asset not named in the signed authorization.

If a client requests anything outside the list, pause and decline until appropriate expertise, a separate written scope, and suitable safeguards are in place.

## Client onboarding checklist
- [ ] Client identity and business contact verified to a reasonable degree.
- [ ] Client confirms they own/control the website or are authorized to commission testing.
- [ ] Signed authorization form is received.
- [ ] Exact hostname and URL are listed.
- [ ] Excluded subdomains, paths, systems, and third-party services are recorded.
- [ ] Permitted date/time and request limit are agreed.
- [ ] Client understands this is a non-intrusive header hygiene review, not a penetration test.
- [ ] Data handling and deletion date are agreed.
- [ ] Fee, deliverable, and delivery date are agreed in writing.
- [ ] No work starts until all required items are complete.

## Delivery checklist
- [ ] Run only the approved single HEAD check.
- [ ] Save the UTC timestamp and exact URL.
- [ ] Do not store passwords, cookies, tokens, personal data, or unrelated information.
- [ ] Review every observation manually; do not copy AI claims without verification.
- [ ] Distinguish observation, potential impact, and recommendation.
- [ ] Include limitations and the exact test performed.
- [ ] Send the report privately to the named client contact.
- [ ] Delete local working data on the agreed date and confirm deletion.

## Honest marketing copy
"NEXORA Website Security Hygiene Review is a beginner-friendly, non-intrusive review of selected HTTP security response headers for website owners. You receive a clear summary of observed headers, practical recommendations, and limitations. This service is not a penetration test or security certification. Work begins only after written authorization and a confirmed scope."

## Sales process
1. Show a sample report generated against your own local lab or a website you own.
2. Contact a small number of businesses with personalized, non-alarmist messages.
3. Ask whether they own/control their website and whether they want the limited review.
4. Send the scope and authorization form before collecting payment or running any test.
5. Confirm the fee, deliverable, and date in writing.
6. Complete only the agreed review and deliver the report.
7. Ask for honest feedback and permission before using any testimonial or logo.

## Revenue reality
No income is guaranteed. The first goal is one satisfied pilot client, not a large revenue claim. Track outreach, replies, paid orders, time spent, refunds, and feedback. If you cannot explain every finding and its limitations, do not sell that review yet.
