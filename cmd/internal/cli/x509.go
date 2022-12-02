// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package cli

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

var errFailedToDecodePEM = errors.New("failed to decode PEM")

// loadCertificate returns the certificate read from path.
func loadCertificate(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errFailedToDecodePEM
	}

	return x509.ParseCertificate(p.Bytes)
}

// loadCertificatePool returns the pool of certificates read from path.
func loadCertificatePool(path string) (certPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pool := make(map[string]*x509.Certificate)

	for rest := bytes.TrimSpace(b); len(rest) > 0; {
		var p *pem.Block

		if p, rest = pem.Decode(rest); p == nil {
			return nil, errFailedToDecodePEM
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}

		pool[string(cert.SubjectKeyId)] = cert
	}

	return pool, nil
}

// certPool is needed because *x509.x509CertPool does not support listing of Certificates.
// Without listing, it is impossible to perform Revocation Checking.
type certPool map[string]*x509.Certificate

func (cc certPool) x509CertPool() *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range cc {
		pool.AddCert(cert)
	}

	return pool
}

func (cc certPool) downloadCertsFromURLs(urls ...string) (certPool, error) {
	for _, certURL := range urls {
		//nolint:gosec
		// Alternative:  GOSEC=gosec -quiet -exclude=G104,G107
		resp, err := http.Get(certURL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get certificate from '%s'", certURL)
		}

		caCertBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot read CA certificate's body frin '%s'", certURL)
		}

		if err := resp.Body.Close(); err != nil {
			return nil, errors.Wrapf(err, "resp closing error: '%s'", err)
		}

		// decode raw data as DER
		cert, err := x509.ParseCertificate(caCertBody)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode certificate from '%s'", certURL)
		}

		// add certs to the chain
		cc[string(cert.SubjectKeyId)] = cert
	}

	return cc, nil
}

/*
Online Certificate Status Protocol - OCSP


The Online Certificate Status Protocol (OCSP) enables applications to
determine the (revocation) state of identified certificates.

RFC: https://www.rfc-editor.org/rfc/rfc6960
*/

const (
	PKIXOCSPNoCheck = "1.3.6.1.5.5.7.48.1.5"
)

var (
	errOCSPQuery       = errors.New("failed to contact OCSP")
	errOCSPUnsupported = errors.New("certificated does not support OCSP")
)

func OnlineRevocationCheck(leaf *x509.Certificate, intermediates certPool, roots certPool) error {
	// validate the leaf certificate.
	if err := validateCertificate(leaf, intermediates, roots); err != nil {
		return err
	}

	// recursively validate the intermediate certificates.
	// the root does not need verification -- it is trusted be default.
	for _, cert := range intermediates {
		if err := validateCertificate(cert, intermediates, roots); err != nil {
			return errors.Wrapf(err, "Subject: '%s'", cert.Subject.String())
		}
	}

	return nil
}

func validateCertificate(cert *x509.Certificate, intermediates certPool, roots certPool) error {
	/*---------------------------------------------------
	 * Retrieve the CA who issued the certificate in question.
	 *---------------------------------------------------*/

	// firstly, look for the issuer in the intermediate certificates.
	issuer, exists := intermediates[string(cert.AuthorityKeyId)]
	if !exists {
		// if not found, look for the issuer on the root certificates.
		issuer, exists = roots[string(cert.AuthorityKeyId)]
		if !exists {
			// if not found anywhere locally, try to download it
			missingCerts, err := roots.downloadCertsFromURLs(cert.IssuingCertificateURL...)
			if err != nil {
				return errors.Wrapf(err, "download cert error")
			}

			// if that does not work either, just abort
			issuer, exists = missingCerts[string(cert.AuthorityKeyId)]
			if !exists {
				return errors.Errorf("cannot find issuer  '%s' for '%s'", cert.Issuer, cert.Subject)
			}
		}
	}

	/*---------------------------------------------------
	 * Ask OCSP for the validity of signer's certificate.
	 * Also make sure that the OCSP is trustworthy.
	 *---------------------------------------------------*/
	ocspCertificate, err := queryOCSP(cert, issuer)
	if err != nil {
		return errors.Wrapf(err, "certificate '%s'", cert.Subject)
	}

	if ocspCertificate != nil {
		// The CA requires us to explicitly trust this certificate
		// RFC-6960 Section: 4.2.2.2.1
		for _, extension := range cert.Extensions {
			if extension.Id.String() == PKIXOCSPNoCheck {
				goto skipOCSPVerification
			}
		}

		// make sure that the OCSP server is trustworthy
		if _, err := ocspCertificate.Verify(
			x509.VerifyOptions{
				Intermediates: intermediates.x509CertPool(),
				Roots:         roots.x509CertPool(),
				KeyUsages: []x509.ExtKeyUsage{
					x509.ExtKeyUsageCodeSigning,
				},
			}); err != nil {
			return errors.Wrapf(err, "cannot verify OCSP server's certificate")
		}

	skipOCSPVerification:
	}

	return nil
}

func queryOCSP(cert, issuer *x509.Certificate) (needsValidation *x509.Certificate, err error) {
	if !issuer.IsCA {
		return nil, errors.Errorf("signer's certificates can only belong to a CA")
	}

	/*---------------------------------------------------
	 * Extract OCSP Server from the certificate in question
	 *---------------------------------------------------*/
	if len(cert.OCSPServer) == 0 {
		return nil, errOCSPUnsupported
	}

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	ocspURL, err := url.Parse(cert.OCSPServer[0])
	if err != nil {
		return nil, errors.Wrapf(err, "canot parse OCSP Server from certificate")
	}

	/*---------------------------------------------------
	 * Create OCSP Request
	 *---------------------------------------------------*/
	opts := &ocsp.RequestOptions{Hash: crypto.SHA256}

	buffer, err := ocsp.CreateRequest(cert, issuer, opts)
	if err != nil {
		return nil, errOCSPQuery
	}

	httpRequest, err := http.NewRequest(http.MethodPost, cert.OCSPServer[0], bytes.NewBuffer(buffer))
	if err != nil {
		return nil, errOCSPQuery
	}

	// Submit OCSP Request
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspURL.Host)

	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, errOCSPQuery
	}

	defer httpResponse.Body.Close()

	/*---------------------------------------------------
	 * Parse OCSP Response
	 *---------------------------------------------------*/
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read response body")
	}

	ocspResponse, err := ocsp.ParseResponse(output, issuer)
	if err != nil {
		return nil, errOCSPQuery
	}

	/*---------------------------------------------------
	 * Certificate Validation
	 *---------------------------------------------------*/

	// The OCSP's certificate is signed by a third-party issuer that we need to verify.
	if ocspResponse.Certificate != nil {
		needsValidation = ocspResponse.Certificate
	}

	// Check validity
	switch ocspResponse.Status {
	case ocsp.Good: // means the certificate is still valid
		return needsValidation, nil

	case ocsp.Revoked: // says the certificate was revoked and cannot be trusted
		return needsValidation, errors.Errorf("certificate revoked at '%s'. Revocation reason code: '%d'",
			ocspResponse.RevokedAt, ocspResponse.RevocationReason)

	default: // states that the server does not know about the requested certificate,
		return needsValidation, errors.Errorf("status unknown. certificate cannot be trusted")
	}
}
