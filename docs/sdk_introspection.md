# AccuKnox SDK static introspection

All findings below were obtained by static package metadata/source inspection. No client method or backend endpoint was invoked.

- Distribution: `accuknox-llm-defense==0.1.8`
- Client: `accuknox_llm_defense.LLMDefenseClient`
- Constructor: `(llm_defense_api_key, user_info="", client_info="", resource_id="", tags=[], base_url=None)`
- `scan_prompt`: `(self, content)`
- `scan_response`: `(self, prompt, content, session_id)`
- HTTP implementation: `requests.post` to `/llm-defence/application-query`
- TLS verification: explicitly disabled using `verify=False`. This explains `urllib3` insecure-request warnings and is a security limitation.
- Timeout: no timeout argument is supplied; requests may wait according to Requests/OS defaults.
- Error handling: `requests.exceptions.RequestException` is converted to an `{"error": ...}` mapping rather than raised.
- Attachment support: **UNSUPPORTED_BY_CURRENT_SDK** in these method signatures/payloads. No attachment field is present.
- Constructor connectivity: constructor decodes the JWT without signature verification and derives the URL; source contains no HTTP call in construction.
- Mutable default: `tags=[]` is a mutable default, though the source only joins it.
- Token handling: JWT issuer is decoded with signature verification disabled to construct the endpoint.

Actual classifier status behavior, server-side regex semantics, Anonymize/Deanonymize placeholder syntax, policy thresholds, sanitization, response repair, authentication, connectivity, and backend TLS behavior are **NOT LIVE-VALIDATED DUE TO ZERO-COST GUARANTEE**.

UsernameRegex backend semantics:

- substring: UNKNOWN — REQUIRES LIVE VALIDATION
- search: UNKNOWN — REQUIRES LIVE VALIDATION
- match: UNKNOWN — REQUIRES LIVE VALIDATION
- fullmatch: UNKNOWN — REQUIRES LIVE VALIDATION
- case-sensitive: UNKNOWN — REQUIRES LIVE VALIDATION
- case-insensitive: UNKNOWN — REQUIRES LIVE VALIDATION

DEANONYMIZE LIVE CORRELATION: **NOT LIVE-VALIDATED DUE TO ZERO-COST GUARANTEE**.
