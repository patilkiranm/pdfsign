module github.com/digitorus/pdfsign

go 1.25.0

// Fork of pkcs7 with SkipSigningTime support for PAdES-BASELINE-B.
// Update pseudo-version after pushing pkcs7 nordic branch:
//   GOPROXY=direct go get github.com/patilkiranm/pkcs7@nordic && go mod tidy
replace github.com/digitorus/pkcs7 => github.com/patilkiranm/pkcs7 v0.0.0-20260413075211-89201701bf6b

require (
	github.com/digitorus/pdf v0.1.2
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7
	github.com/mattetti/filebuffer v1.0.1
	golang.org/x/crypto v0.49.0
	golang.org/x/text v0.35.0
)
