# API Security fundamentals

## Why API Security?

API's are present everywhere.

Some facts:
- 83% of all internet traffic is API traffic
- API attacks will become th emost frequent attack factor
- 4% of testing on API's is security testing

How API's get attacked
- Utilize the application and monitor API traffic
- Use the API calls directly
- They look for:
  - More permission that required
  - Vulnerabilities within the API
- Simpler attack pattern

## OWASP API Top 10

Top 10:
- Broken Object Level Authorization
- Broken Authentication
- Broken Object Property Level Authorization
- Unrestricted Resource Consumption
- Broken Function Level Authorization
- Unrestricted Access to Sensitive Business Flows
- Server Side Request Forgery
- Security Misconfiguration
- Improper Inventory Management
- Unsafe Consumption of APIs

### Broken Object Level Authorization (BOLA)

Can one user access another user's data

Prevention
- Discuss authorization rules during API design phase
- Review business requirements and define data access policies
- Enforce authorization controls at application logic layer
- Implement automated, pre-production testing to find BOLA flaws

### Broken Authentication

Prevention
- Define authentication policies based on business requirements
- Consider data sensitivity in policies
- Implement continuous testing to identify gaps and weaknesses
- Do not assume APIs are hidden/will not be found

### Broken Object Property Level Authorization (BOPLA)

Modifying properties of objects, for example setting account type from "user" to "admin".

Prevention
- Ensure user can only access legitimate and permitted fields
- Return only minimum amount of data required for the use case
- Define data requirements in API specifications
- Test to validate policy compliance
- Implement proper controls enforced to prevent mass assignment exploits
- Test controls to identify logic flaws

### Unrestricted Resource Consumption

Prevention
- Implement traffic controls
- Test effectiveness of controls
- Note: rate limiting is a velocity control, not a volume control
  - Attackers are clever and determined
  - Will evade detection by limiting requests velocity
  - Breaches can take months

### Broken Function Level Authorization

Replace passive methods like `GET` with active like `PUT` or `DELETE`.

Prevention
- Identify and prioritize functions that expose high sensitivity capability
- Develop controls to limit access
- Implement continuous release testing to ensure proper behavior
- Review RBAC permissions across all user types and detect drift

### Unrestricted Access to Sensitive Business Flows

Can it be used to work as **not** designed.

Prevention
- Consider not just how your application is meant to work
- Avoid use of incremental IDs
- Train API owners and developers to consider non "happy path" usage
- Think like a hacker, how can your app be abused or misused

### Server Side Request Forgery (SSRF)

Trick the server into going somewhere it should not.

Prevention
- Utilize least privilege
- Do not trust any inputs without input validation and sanitization
- Validate **all** user-supplied information, including URL parameters
- Simulate SSRF attacks during QA/testing to identify any vulnerabilities

### Server Misconfiguration

Prevention
- Implement hardening procedures
- Enforce proper headers and policies: CORS, HSTS, Rate limit
- Ensure error messages are helpful but not revealing
- Prevent path traversal and server information leakage
- Routinely review configurations
- Test configuration to ensure proper settings; discover drift

### Improper Inventory Management

Prevention
- Define common and standard processes for API development
- Create a complete inventory of APIs
- Identify internally developen APIs as well as 3rd party APIs
- Deploy/manage all APIs in Gateway
- Define versioning rules and retirement
- Make sure all parties upgrade to the latest version
- Periodically audit 3rd party access

### Unsafe Consumption of APIs

Prevention
- Maintain accurate inventory of 3rd party APIs
- Do not assume 3rd party APIs aresafe; secure them like your own APIs
- Validate data returned by 3rd party APIs
- Test authorization rules
- Request vulnerability testing reports from vendors
- Evaluate security controls of a 3rd party API

## API Attack Analysis

API OWASP 1, 2 and 3 are responsible for 90% of API breaches.

Threat Modeling
- Identify
- Assess
- Probability
- Impact
- Mitigation

## Three Pillars of API security

Three Pillars
- Governance
- Monitoring
  - Runtime Protection
  - Threat Detection
  - Control Validation
- Testing

## Application Security Technology

SAST, DAST

SCA, Container Security

Web App Firewall

API Security

## Best practices

Best practices
- Do not trust anything
- Do validate all inputs
- Do not reveal useful info in error messages
- Do expect attackers to find your APIs
- Do not have hidden or unadvertised features
- Do not filter data in the UI. Control it at the application level
- Do use Gateways to control access and traffic
- Do not forget authentication & authorization
- Do require API documentation
- Do continuously test, even pre-production