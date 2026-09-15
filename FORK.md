# Fork: patilkiranm/pdfsign

Upstream: [github.com/digitorus/pdfsign](https://github.com/digitorus/pdfsign)

## Branch strategy

- `main` — tracks upstream exactly (never commit custom changes)
- `nordic` — default branch, contains patches rebased on `main`

Rebasing moves `nordic` (force-push); the previous tip is kept as
`nordic-pre-rebase` until the next rebase.

## Dependencies

None beyond upstream's. Upstream's own `github.com/digitorus/pkcs7` carries
`SkipSigningTime`, so the earlier `patilkiranm/pkcs7` replace is gone.

## Changes

Three patches, each one commit on top of `main`.

### 1. Injectable HTTP client for the RFC 3161 request (`sign/types.go`, `sign/pdfsignature.go`)

**Changed:** `TSA.HTTPClient *http.Client`. When set, `GetTSA` performs the timestamp POST with it; when nil, upstream behaviour is unchanged (a bare client, bounded by `defaultHTTPTimeout` unless `SignData.Context` carries a deadline).

**Rationale:** upstream bounds the call through `SignData.Context` and a default timeout, but a caller cannot reuse a pooled transport or apply its own client policy. The Nordic platform passes an `httpx`-managed client, consistent with its CSC, DSS and eID clients.

### 2. Xref stream listed in its own `/Index` and counted in `/Size` (`sign/pdfxref_stream.go`)

**Changed:** `writeXrefStream` records the xref stream's own entry before encoding, so the stream appears in its own `/Index` section and `/Size` is one past it (never below the input's `/Size`). Upstream numbers the stream with `AddObject` after the header is written: it is absent from `/Index`, and `/Size` equals its object number whenever the input's `/Size` is its highest object number plus one (pdfcpu output, and the xref-stream fixtures in `testfiles/`).

**Rationale:** PDFBox, which EU DSS uses to append the `/DSS` revision, numbers an incremental update's objects from the highest object number in the parsed xref table and ignores `/Size`. An xref stream is in that table only if its own `/Index` lists it, so PDFBox handed the stream's number out again, to the `/DSS` dictionary. The final xref resolved correctly and signatures stayed valid, but readers that cache xref streams by object number (pypdf) resolve `/DSS` to the old xref stream. Correcting `/Size` alone does not change PDFBox's numbering; listing the stream does (verified with PDFBox 3.0.6 `saveIncremental`). Covered by `TestXrefStreamCoversItself`; `TestWriteXrefTypeStream` pins the self-entry.

### 3. Retry hygiene for the signature-too-long loop (`sign/sign.go`, `sign/pdfsignature.go`)

**Changed:** each attempt of upstream's retry loop starts from the caller's `SignData.RevocationData` (a slice clone, so attempts never write into the caller's arrays), and the placeholder grows by `diff + 2` instead of `diff + 1`.

**Rationale:** upstream's `resetContext` clears xref state but not revocation data, so `RevocationFunction` appended its CRLs and OCSP responses again on every attempt; and `diff + 1` left the zero-padded `/Contents` hex string with an odd digit count, which readers reject as malformed. Each attempt still calls the signer and the TSA; a retry costs a second timestamp. Covered by `TestSignPDFRetryStartsClean`, which forces the retry from a two-digit placeholder on an xref-table and an xref-stream fixture; reverting either part fails it.

## Absorbed by upstream (no longer patched here)

- `/SubFilter /ETSI.CAdES.detached`, mandatory `/M`, `SkipSigningTime`, no Adobe revocation attribute for PAdES: upstream's `SignData.SubFilter = SubFilterETSICAdESDetached` (opt-in; the zero value is the legacy `/adbe.pkcs7.detached` profile, so callers must set it).
- `SignData.Context` bounding the TSA request: upstream.
- Clean-state retry: upstream's `SignPDF` loops with `resetContext` (the two leftovers are change 3).
- Signature size estimate: upstream sizes the placeholder from the signer's public key instead of the certificate's signature algorithm.

## Upstream PR status

- [ ] `TSA.HTTPClient` — PR as a small feature
- [ ] Xref stream missing from its own `/Index` and `/Size` — PR as bug fix
- [ ] Retry: revocation data restored per attempt, even placeholder growth — PR as bug fix
