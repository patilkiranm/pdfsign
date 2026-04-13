# Fork: patilkiranm/pdfsign

Upstream: [github.com/digitorus/pdfsign](https://github.com/digitorus/pdfsign)

## Branch strategy

- `main` — tracks upstream exactly (never commit custom changes)
- `nordic` — default branch, contains patches rebased on `main`

## Dependencies

This fork depends on [patilkiranm/pkcs7](https://github.com/patilkiranm/pkcs7) (branch `nordic`) for the `SkipSigningTime` feature. The `go.mod` contains a `replace` directive for this.

## Changes

All changes are in `sign/pdfsignature.go` and are required for PAdES-BASELINE-B (ETSI EN 319 142-1) compliance.

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

## Upstream PR status

- [ ] Configurable SubFilter — open issue to discuss API design (add `SubFilter` field to `SignData`)
- [ ] Conditional revocation attribute — PR as bug fix
- [ ] Always write `/M` — include in SubFilter discussion
