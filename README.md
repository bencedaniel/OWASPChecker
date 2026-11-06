# OWASPChecker

OWASPChecker is an automated API security testing service for OpenAPI-described applications. It discovers API endpoints from an OpenAPI document, authenticates with supplied test accounts, collects valid resource identifiers, and runs targeted OWASP API Security Top 10 checks.

The scanner is designed to work against different API implementations rather than a single target application. Endpoint paths, request schemas, login fields, tokens, and resource identifiers are derived from the target API's OpenAPI specification and responses whenever possible.

## Features

- OpenAPI 3 specification loading
- Automatic authentication endpoint and credential-field discovery
- Support for common login identifiers such as `username`, `email`, `login`, and `identifier`
- Admin and tester authentication contexts
- Resource ID reconnaissance from JSON API responses
- Support for MongoDB ObjectIds, UUIDs, numeric IDs, and common custom ID fields
- Category-aware path parameter resolution
- Automatic token refresh after protected endpoint `401` responses
- Scan reports persisted in MongoDB
- Swagger UI and OpenAPI documentation for the scanner API
- Background scan execution with report status tracking

## OWASP API checks

The scanner includes checks for:

- **API1:2023 - Broken Object Level Authorization (BOLA)**
- **API2:2023 - Broken Authentication**
- **API3:2023 - Broken Object Property Level Authorization (BOPLA)**
- **API4:2023 - Unrestricted Resource Consumption**
- **API5:2023 - Broken Function Level Authorization (BFLA)**
- **API6:2023 - Unrestricted Access to Sensitive Business Flows**
- **API7:2023 - Server-Side Request Forgery (SSRF)**
- **API8:2023 - Security Misconfiguration**
- **API9:2023 - Improper Inventory Management**
- **API10:2023 - Unsafe Consumption of APIs**

The checks are heuristic security probes. A reported finding should be reviewed against the target application's behavior and business requirements.

## How it works

1. The scanner receives a target URL, an OpenAPI specification URL, and test credentials.
2. The OpenAPI specification is loaded and its operations are extracted.
3. Login endpoints and request field names are inferred from paths and request schemas.
4. Admin and tester tokens are requested.
5. Reconnaissance calls suitable unauthenticated list endpoints with the admin token.
6. IDs are grouped by their resource category and source endpoint.
7. Path parameters such as `{id}` are resolved using IDs from the matching category.
8. Each OWASP module runs only against relevant endpoints.
9. Findings and scan status are stored in MongoDB.

Endpoints without a suitable collected identifier are skipped instead of being called with an unrelated or fabricated ID.

## Requirements

- Node.js 20 or newer
- MongoDB
- A target API described by an OpenAPI or Swagger JSON document
- Dedicated test credentials for the target API:
  - a normal user account
  - an administrator account

Use isolated test accounts and a non-production target. Some checks send write requests and may create or modify test data.

## Installation

```bash
npm install
```

Create a `.env` file:

```env
PORT=3002
MONGODB_URI=mongodb://127.0.0.1:27017/owaspchecker
JWT_SECRET=replace-this-with-a-long-random-secret
```

Start the service:

```bash
npm start
```

The scanner API is available at:

```text
http://localhost:3002
```

Interactive API documentation is available at:

```text
http://localhost:3002/api-docs
```

## Starting a scan

Authenticate against the scanner API, then create a scan with `POST /api/scans`.

Example request:

```json
{
  "targetUrl": "https://target.example",
  "openApiSpecUrl": "https://target.example/api-docs.json",
  "testUserCredentials": {
    "email": "tester@example.test",
    "password": "test-password"
  },
  "testAdminCredentials": {
    "username": "admin",
    "password": "admin-password"
  }
}
```

The credential identifier may be supplied as `username`, `email`, `login`, `identifier`, or `user`. The password field remains `password`.

The endpoint returns `202 Accepted` and a scan ID:

```json
{
  "message": "A scan has been started.",
  "scanId": "scan-id",
  "status": "pending"
}
```

Retrieve the scan status and findings with:

```text
GET /api/scans/{scanId}
```

## Reconnaissance and ID resolution

Reconnaissance collects IDs from successful, parameter-free `GET` endpoints. IDs are associated with the endpoint and a resource category. Supported identifiers include values in fields such as:

- `id`
- `_id`
- `userId`
- `resource_id`
- `uuid`
- `identifier`

For a path such as `/accounts/{accountId}/devices/{deviceId}`, the resolver selects IDs based on the nearest matching resource category. This prevents a device endpoint from accidentally receiving an account or user ID.

## Testing considerations

The scanner should only be used against systems for which you have explicit authorization. Recommended practice:

- use a local or dedicated staging environment;
- create separate admin and tester accounts for each scan;
- take a database backup before testing state-changing endpoints;
- review API6, API7, and API10 results manually;
- monitor target application logs during a scan;
- avoid using production credentials or production data.

Some checks intentionally submit malformed, repeated, or security-oriented payloads. The scanner avoids known self-destructive account paths such as `DELETE` operations on `/me`, but target-specific side effects cannot be eliminated for every API.

## Development

Run the test suite:

```bash
npm test -- --run
```

The tests cover the OWASP check modules and path parameter behavior.

## Project structure

```text
controllers/              Scan and authentication request handlers
models/                   MongoDB schemas
routers/                  Express routes and Swagger annotations
services/reconEngine.js   Login discovery, authentication, and ID reconnaissance
services/pathResolver.js  Category-aware path parameter resolution
services/smartFetch.js    Authenticated requests and token refresh
services/owaspChecks/     OWASP API security checks
tests/                    Unit tests for scanner modules
```

## Limitations

- Detection is based on OpenAPI metadata, response data, and heuristics.
- APIs with no usable OpenAPI specification require additional integration work.
- Authentication flows requiring OAuth redirects, MFA, client certificates, or custom non-JSON protocols may not be discovered automatically.
- Business-flow tests cannot fully understand target-specific transactional side effects.
- A finding is an indication for investigation, not proof of exploitability in every deployment.

## License

This project is intended for authorized security testing, education, and development use.
