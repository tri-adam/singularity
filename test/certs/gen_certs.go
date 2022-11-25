// Copyright (c) 2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the LICENSE.md file
// distributed with the sources of this project regarding your rights to use or distribute this
// software.

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var start = time.Date(2020, 4, 1, 0, 0, 0, 0, time.UTC)

// createCertificate creates a new X.509 certificate.
func createCertificate(tmpl, parent *x509.Certificate, pub, pri any) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, pri)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// createRoot creates a self-signed root certificate using the supplied key.
func createRoot(start time.Time, key crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "root",
		},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	return createCertificate(tmpl, tmpl, key.(crypto.Signer).Public(), key)
}

// createIntermediate creates an intermediate certificate using the supplied parent and keys.
func createIntermediate(start time.Time, key crypto.PublicKey, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "intermediate",
		},
		NotBefore:             start,
		NotAfter:              start.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	return createCertificate(tmpl, parent, key, parentKey)
}

// createIntermediate creates a leaf certificate using the supplied parent and keys.
func createLeaf(start time.Time, key crypto.PublicKey, parent *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Sylabs Inc."},
			CommonName:   "leaf",
		},
		NotBefore: start,
		NotAfter:  start.AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
		MaxPathLenZero: true,
	}

	return createCertificate(tmpl, parent, key, parentKey)
}

// writeCerts generates certificates and writes them to disk.
func writeCerts() error {
	pem, err := os.ReadFile(filepath.Join("..", "keys", "private.pem"))
	if err != nil {
		return err
	}

	pri, err := cryptoutils.UnmarshalPEMToPrivateKey(pem, cryptoutils.SkipPassword)
	if err != nil {
		return err
	}

	pub := pri.(crypto.Signer).Public()

	root, err := createRoot(start, pri)
	if err != nil {
		return err
	}

	intermediate, err := createIntermediate(start, pub, root, pri)
	if err != nil {
		return err
	}

	leaf, err := createLeaf(start, pub, intermediate, pri)
	if err != nil {
		return err
	}

	outputs := []struct {
		cert *x509.Certificate
		path string
	}{
		{
			cert: root,
			path: "root.pem",
		},
		{
			cert: intermediate,
			path: "intermediate.pem",
		},
		{
			cert: leaf,
			path: "leaf.pem",
		},
	}

	for _, output := range outputs {
		b, err := cryptoutils.MarshalCertificateToPEM(output.cert)
		if err != nil {
			return err
		}

		if err := os.WriteFile(output.path, b, 0o644); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if err := writeCerts(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
