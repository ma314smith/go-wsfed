package wsfed

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/beevik/etree"
	"github.com/ma314smith/signedxml"
)

// Config maintains the configuration for sending/receiving WSFed messages.
//
// Either an IDPEndpoint or MetadataURL should be specified.
//
// If MetadataURL is provided, it will be parsed for a PassiveRequestorEndpoint.
// The certificates in the metadata can optionally be added to the TrustedCerts,
// or the certs can be specified directly.
//
// If MetadataRefreshIntervalSeconds is set, the metadata will be polled at that
// frequency to update the configuration.  This is usefull for certificate
// rotation when the metadata certs are trusted (MetadataCertsAreTrusted).
type Config struct {
	IDPEndpoint                    string
	MetadataURL                    string
	MetadataCertsAreTrusted        bool
	MetadataRefreshIntervalSeconds time.Duration
	Realm                          string
	TrustedCerts                   []x509.Certificate
}

func (c *Config) updateConfigFromMetadata() {
	body := c.getMetadata()

	certs := c.validateMetadata(body)
	if c.MetadataCertsAreTrusted {
		for _, cert := range certs {
			c.AddTrustedCert(cert)
		}
	}

	c.IDPEndpoint = c.getIDPEndpointFromMetadata(body)
}

func (c *Config) getMetadata() string {
	resp, err := http.Get(c.MetadataURL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

func (c *Config) validateMetadata(body string) (signingCert []x509.Certificate) {
	validator, err := signedxml.NewValidator(body)
	if err != nil {
		panic(err)
	}
	err = validator.Validate()
	if err != nil {
		panic(err)
	}

	certs := validator.Certificates
	return certs
}

func (c *Config) getIDPEndpointFromMetadata(body string) string {
	doc := etree.NewDocument()
	err := doc.ReadFromString(body)
	if err != nil {
		panic(err)
	}
	endpointElement := doc.FindElement("//PassiveRequestorEndpoint/EndpointReference/Address[1]")
	if endpointElement == nil {
		panic(errors.New("go-wsfed: unable to find Passive Requestor Endpoint in metadata"))
	}
	return endpointElement.Text()
}

// AddTrustedCert adds a cert to Config.TrustedCerts. If the cert already exists
// in the array, then no action is taken.
func (c *Config) AddTrustedCert(cert x509.Certificate) {
	for _, t := range c.TrustedCerts {
		if t.Equal(&cert) {
			return
		}
	}
	c.TrustedCerts = append(c.TrustedCerts, cert)
}
