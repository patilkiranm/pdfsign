package sign

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"
)

// TestSignPDFRetryStartsClean forces the "signature too long" retry in
// replaceSignature by starting from a two-digit placeholder. The retry rebuilds
// the output from the input, so object numbering and revocation data from the
// abandoned attempt must not carry over into it.
func TestSignPDFRetryStartsClean(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	pkey, cert := pki.IssueLeaf("Test")

	for _, name := range []string{"testfile20.pdf", "testfile17.pdf"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.Open("../testfiles/" + name)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close() }()
			finfo, err := input.Stat()
			if err != nil {
				t.Fatal(err)
			}
			rdr, err := pdf.NewReader(input, finfo.Size())
			if err != nil {
				t.Fatal(err)
			}

			var output bytes.Buffer
			context := SignContext{
				PDFReader:  rdr,
				InputFile:  input,
				OutputFile: &output,
				SignData: SignData{
					Signature: SignDataSignature{
						Info:     SignDataSignatureInfo{Name: "Test", Date: time.Now()},
						CertType: ApprovalSignature,
					},
					DigestAlgorithm:   crypto.SHA256,
					Signer:            pkey,
					Certificate:       cert,
					CertificateChains: [][]*x509.Certificate{{cert}},
					RevocationFunction: func(_, _ *x509.Certificate, i *revocation.InfoArchival) error {
						return i.AddCRL([]byte{0x30, 0x00})
					},
				},
				SignatureMaxLengthBase: 2,
			}
			if err := context.SignPDF(); err != nil {
				t.Fatal(err)
			}
			if context.SignatureMaxLengthBase == 2 {
				t.Fatal("placeholder was large enough; the retry path was not exercised")
			}

			if got := len(context.SignData.RevocationData.CRL); got != 1 {
				t.Errorf("revocation data holds %d CRLs, want 1 (one per certificate)", got)
			}
			if got, want := len(context.newXrefEntries), newObjectsWritten(t, output.Bytes()[finfo.Size():], context.updatedXrefEntries); got != want {
				t.Errorf("xref lists %d new objects, update writes %d", got, want)
			}

			signed := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(signed, output.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(signed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := verify.VerifyFile(f); err != nil {
				t.Fatalf("signed output does not verify: %v", err)
			}
		})
	}
}

// newObjectsWritten counts the object definitions in an incremental update that
// are not rewrites of existing objects.
func newObjectsWritten(t *testing.T, update []byte, updated []xrefEntry) int {
	t.Helper()
	rewritten := map[string]bool{}
	for _, e := range updated {
		rewritten[strconv.Itoa(int(e.ID))] = true
	}
	n := 0
	for _, m := range regexp.MustCompile(`(?m)^(\d+) 0 obj`).FindAllSubmatch(update, -1) {
		if !rewritten[string(m[1])] {
			n++
		}
	}
	return n
}
