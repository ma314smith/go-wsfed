// Package wsfed provides functionality for generating a redirect url to an IDP,
// and parsing Tokens returned from the IDP.
package wsfed

import (
	"errors"
	"log"
	"net/url"
	"time"

	"github.com/ma314smith/signedxml"
)

// WSFed provides request and response handling for WS-Federation messages
type WSFed struct {
	config *Config
}

// New returns a config initialized *WSFed
func New(config *Config) *WSFed {
	if config.Realm == "" {
		panic(errors.New("go-wsfed: Realm is required"))
	}
	if config.IDPEndpoint == "" && config.MetadataURL == "" {
		panic(errors.New("go-wsfed: Either IDPEndpoint or MetadataURL must be provided"))
	}
	if (len(config.TrustedCerts) < 1 && config.MetadataURL == "") ||
		(len(config.TrustedCerts) < 1 && !config.MetadataCertsAreTrusted) {
		panic(errors.New("go-wsfed: No trusted certs were added, and MetadataCertsAreTrusted is false"))
	}
	if config.MetadataURL != "" {
		config.updateConfigFromMetadata()
	}
	if config.MetadataRefreshIntervalSeconds > 0 {
		go metadataPoller(config)
	}
	return &WSFed{config: config}
}

// metadataPoller polls the metadata in a loop when MetadataRefreshIntervalSeconds
// has been configured. this can be used to get the lastest trusted certificates
// from the IDP.
func metadataPoller(config *Config) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Error refreshing metatdata: %s", r)
			log.Printf("Another refresh will be attempted in %v",
				config.MetadataRefreshIntervalSeconds*time.Second)
			metadataPoller(config)
		}
	}()
	for {
		time.Sleep(config.MetadataRefreshIntervalSeconds * time.Second)
		config.updateConfigFromMetadata()
	}
}

// GetRequestURL constructs the url that the requestor can be sent to for authentication
func (w *WSFed) GetRequestURL(params RequestParameters) (requestURL string, err error) {
	request, err := url.Parse(w.config.IDPEndpoint)
	if err != nil {
		return "", err
	}

	query := url.Values{}
	query.Add("wa", params.Wa)
	query.Add("wtrealm", params.Wtrealm)
	if params.Wreply != "" {
		query.Add("wreply", params.Wreply)
	}
	if params.Wctx != "" {
		query.Add("wctx", params.Wctx)
	}
	if params.Wct != "" {
		query.Add("wct", params.Wct)
	}
	if params.Wfresh != "" {
		query.Add("wfresh", params.Wfresh)
	}

	request.RawQuery = query.Encode()
	return request.String(), nil
}

// GetDefaultRequestParameters returns a RequestParameters object with wa set to
// "wsignin1.0" and Wtrealm set to the WSFed.config.Realm
func (w *WSFed) GetDefaultRequestParameters() RequestParameters {
	return RequestParameters{
		Wa:      "wsignin1.0",
		Wtrealm: w.config.Realm,
		Wct:     convertTimeToISO8601(time.Now().UTC()),
	}
}

// RequestParameters holds the paramter values for the WSFed GET/POST request
type RequestParameters struct {
	Wa      string
	Wtrealm string
	Wreply  string
	Wctx    string
	Wct     string
	Wfresh  string
}

// ParseResponse validates the xml digest and signature, and returns the claims
func (w *WSFed) ParseResponse(wresult string) (claims Claims, err error) {
	if err = w.validateSignedXML(wresult); err != nil {
		return claims, err
	}

	token, err := newToken(wresult, w.config.Realm)
	if err != nil {
		return claims, err
	}

	if err = token.Validate(); err != nil {
		return claims, err
	}

	claims, err = token.GetClaims()

	return claims, err
}

func (w *WSFed) validateSignedXML(wresult string) error {
	validator, err := signedxml.NewValidator(wresult)
	if err != nil {
		return err
	}

	err = validator.Validate()
	if err != nil {
		return err
	}

	cert := validator.SigningCert()

	for _, c := range w.config.TrustedCerts {
		if c.Equal(&cert) {
			return nil
		}
	}

	return errors.New("go-wsfed: The certificate used to sign the response was " +
		"not found in WSFed.config.TrustedCerts")
}
