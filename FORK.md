# Fork: patilkiranm/pdfsign

Upstream: [github.com/digitorus/pdfsign](https://github.com/digitorus/pdfsign)

## Branch strategy

- `main` — tracks upstream exactly (never commit custom changes)
- `nordic` — default branch, contains patches rebased on `main`

## Dependencies

This fork depends on [patilkiranm/pkcs7](https://github.com/patilkiranm/pkcs7) (branch `nordic`) for the `SkipSigningTime` feature. The `go.mod` contains a `replace` directive for this.

## Changes

Changes 1–4 are in `sign/pdfsignature.go` and are required for PAdES-BASELINE-B (ETSI EN 319 142-1) compliance. Change 5 (`sign/types.go` + `sign/pdfsignature.go`) is a resilience hardening of the TSA HTTP call. Change 6 (`sign/pdfxref_stream.go`) is a PDF structure bug fix.

### 1. SubFilter: ETSI.CAdES.detached (line 31)

**Changed:** `/SubFilter /adbe.pkcs7.detached` to `/SubFilter /ETSI.CAdES.detached`

**Rationale:** The SubFilter must be set before hash computation. A post-signing byte replacement would invalidate the CMS message-digest because the SubFilter string is within the signed ByteRange. ETSI.CAdES.detached is required for PAdES-BASELINE-B signatures.

### 2. Always write PDF /M entry (lines 169-178)

**Changed:** Removed the `context.SignData.TSA.URL == ""` condition — `/M` is now always written when `Date` is set.

**Rationale:** For PAdES-BASELINE-B, the signing time MUST be in the PDF `/M` entry (not in CMS signing-time attribute). The old condition skipped `/M` when a TSA was configured, but PAdES requires it regardless. The ISO 32000-2 caveat about TSA applies to ETSI.RFC3161 SubFilter, not ETSI.CAdES.detached.

### 3. Conditional Adobe revocation attribute (lines 325-333)

**Changed:** Only include Adobe revocation data attribute (OID 1.2.840.113583.1.1.8) when CRL or OCSP data is non-nil.

**Rationale:** An empty revocation attribute (empty SEQUENCE) as the first signed attribute breaks CAdES parsers in EU DSS, causing them to fail to detect subsequent attributes like signing-time and ESSCertIDv2.

### 4. SkipSigningTime in signer config (line 339)

**Changed:** Set `SkipSigningTime: true` in `pkcs7.SignerInfoConfig`.

**Rationale:** PAdES-BASELINE-B requires CMS signing-time cardinality == 0. Depends on the pkcs7 fork.

### 5. Bounded, injectable, context-aware TSA request (`GetTSA`)

**Changed (`sign/types.go` + `sign/pdfsignature.go`):**
- Added an optional `HTTPClient *http.Client` field to the `TSA` struct. `GetTSA` uses it, falling back to `&http.Client{Timeout: defaultTSATimeout}` (30s) when nil.
- Added an optional `Context context.Context` field to `SignData`. `GetTSA` now builds the request with `http.NewRequestWithContext(SignData.Context, …)` (falling back to `context.Background()` when nil) instead of `http.NewRequest`.

**Rationale:** The upstream `GetTSA` builds a bare `&http.Client{}` (no timeout) and a request with no context, so a TSA that accepts the TCP connection then stalls before responding blocks the signing goroutine indefinitely — the default transport bounds only the dial. In an async signing worker with a small fixed pool, a few stalled timestamp calls can saturate every slot and halt signing service-wide. There was also no way for the caller to supply a configured/pooled client.

Injecting `TSA.HTTPClient` lets the caller control the timeout and reuse a pooled transport (the Nordic platform passes an `httpx`-managed client, consistent with its CSC/DSS/Signicat/Gotenberg clients); `SignData.Context` lets a caller deadline/cancellation (e.g. a job timeout) abort an in-flight POST. Both fields are optional and backward compatible — a nil client preserves prior behaviour except for the added 30s default ceiling, and a nil context preserves prior behaviour exactly.

### 6. Xref stream `/Size` counts the xref stream itself

**Changed (`sign/pdfxref_stream.go`):** `writeXrefStreamHeader` sets `/Size` to one more than the xref stream's own object number (never below the input's `/Size`), instead of `ItemCount + len(newXrefEntries) + 1`.

**Rationale:** The xref stream is numbered by `addObject` after its header is written, so the old formula made `/Size` equal the xref stream's object number whenever the input's `/Size` was its highest object number plus one (pdfcpu output, and both xref-stream fixtures in `testfiles/`). ISO 32000 requires `/Size` to exceed every object number used in the section. A following incremental writer allocates from `/Size`: EU DSS (PDFBox) placed its `/DSS` dictionary at the xref stream's number, and readers that cache xref streams by object number (pypdf) then resolve `/DSS` to the xref stream and find no validation data. Signatures stayed valid; the defect was structural. Covered by `TestXrefStreamSizeCoversItself`; `TestWriteXrefTypeStream` previously pinned the undercount.

## Upstream PR status

- [ ] Configurable SubFilter — open issue to discuss API design (add `SubFilter` field to `SignData`)
- [ ] Conditional revocation attribute — PR as bug fix
- [ ] Always write `/M` — include in SubFilter discussion
- [ ] Bounded/context-aware TSA request — PR as bug fix (no-timeout bare client is a latency/liveness hazard)
- [ ] Xref stream `/Size` undercount — PR as bug fix (upstream main has the same formula)
