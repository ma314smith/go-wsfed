package wsfed

import (
	"errors"
	"testing"

	"github.com/ma314smith/etree"
	. "github.com/smartystreets/goconvey/convey"
)

func TestGetRequestURL(t *testing.T) {
	Convey("Given valid config and request objects", t, func() {
		config := Config{}
		config.MetadataURL = "https://signin.blackbaud.com/wsfederation/metadata"
		config.MetadataCertsAreTrusted = true
		config.MetadataRefreshIntervalSeconds = 10
		config.Realm = "http://account.blackbaud.com"
		sso := New(&config)
		rp := sso.GetDefaultRequestParameters()
		rp.Wreply = "http://account.blackbaud.com"
		rp.Wctx = "test"
		rp.Wct = "2006-01-02T15:04:05Z"
		rp.Wfresh = "0"
		Convey("When GetRequestURL is called", func() {
			url, err := sso.GetRequestURL(rp)
			Convey("Then a url is returned without error", func() {
				So(err, ShouldBeNil)
				So(url, ShouldEqual, "https://signin.blackbaud.com/WSFEDERATION/ACTION?wa=wsignin1.0&wct=2006-01-02T15%3A04%3A05Z&wctx=test&wfresh=0&wreply=http%3A%2F%2Faccount.blackbaud.com&wtrealm=http%3A%2F%2Faccount.blackbaud.com")
			})
		})
	})
}

var wresult = `<trust:RequestSecurityTokenResponseCollection xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><trust:RequestSecurityTokenResponse><trust:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2015-10-05T13:22:22.500Z</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2015-10-05T14:22:22.500Z</wsu:Expires></trust:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>http://account.blackbaud.com/</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><trust:RequestedSecurityToken><saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="_d8559c80-cb32-40fa-b530-7b3c9121bd27" Issuer="Blackbaud Authentication Service" IssueInstant="2015-10-05T13:22:22.500Z" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:Conditions NotBefore="2015-10-05T13:22:22.500Z" NotOnOrAfter="2015-10-05T14:22:22.500Z"><saml:AudienceRestrictionCondition><saml:Audience>http://account.blackbaud.com/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier>6ef81ad2-99f8-4c42-996c-def1d98db711</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName="emailaddress" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>wsfedtest@outlook.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="givenname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>WSFed</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="surname" AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"><saml:AttributeValue>Test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><Reference URI="#_d8559c80-cb32-40fa-b530-7b3c9121bd27"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><DigestValue>nAW5CZ02C3v8KD6oCbVI9+zhqh3/UUKKnxWBtggHVys=</DigestValue></Reference></SignedInfo><SignatureValue>WoT76nUK0Pwjfe8O6oTGoSLsWiMbcYI60EB8RvYrF0kHupOsfz1cR3JcRJFT7L7As0kGQSPR3LNz+yEU9KZoYabpvv/Br+ydFxtLSFepJU/gsJaR2AMGIF2QmQMC9wE2EU6e72z2XizPbTNfGh40TuckryUEK8yP0lPFUstWRLH7TW9kimZkH+hXItx2cMPNBpN/w3Y5YbCnOVX0HLIh9PGPkZfqenFUnjUGBPNRpoMhcPg7jn5CJ/RM3Od68uSUFA9dEAYVLoJbPT+zsN88ZmnzKD3WwDEPFZXJjcecuKs6EE22qcQ2ha/eb7Im5Wjn1em2jeH8t7NEv6jGmLBBtA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDNzCCAh+gAwIBAgIQQVK+d/vLK4ZNMDk15HGUoTANBgkqhkiG9w0BAQ0FADAoMSYwJAYDVQQDEx1CbGFja2JhdWQgQXV0aGVudGljYXRpb24gMjAyMjAeFw0wMDAxMDEwNDAwMDBaFw0yMjAxMDEwNDAwMDBaMCgxJjAkBgNVBAMTHUJsYWNrYmF1ZCBBdXRoZW50aWNhdGlvbiAyMDIyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArgByjSPVvP4DLf/l7QRz7G7Dhkdns0QjWslnWejHlFIezfkJ4NGPp0+5CRCFYBqAb7DhqyK77Ek5xdzmwgYb1X6GD6UDltWvN5BBFAw69I6/K0WjguFUxk19T7xdc8vTCNAMi+6Ys49O3EBNnI2fiqDoBdMjUTud1F04QY3N2rZWkjMrHV+CnzhoUwqsO/ABWrDbkPzBXdOOIbsKH0k0IP8q2+35pe1y2nxtB9f1fCyCmbUH2HINMHahDmxxanTW5Jy14yD/HSRTFQF9JMTeglomWq5q9VPx0NjsEJR+B5IkRCTf75LoYrrr/fvQm3aummmYPdHauXCBrcm0moX4ywIDAQABo10wWzBZBgNVHQEEUjBQgBDCHOfardZfhltQSbLqsukZoSowKDEmMCQGA1UEAxMdQmxhY2tiYXVkIEF1dGhlbnRpY2F0aW9uIDIwMjKCEEFSvnf7yyuGTTA5NeRxlKEwDQYJKoZIhvcNAQENBQADggEBADrOhfRiynRKGD7EHohpPrltFScJ9+QErYMhEvteqh3C48T99uKgDY8wTqv+PI08QUSZuhmmF2d+W7aRBo3t8ZZepIXCwDaKo/oUp2h5Y9O3vyGDguq5ptgDTmPNYDCwWtdt0TtQYeLtCQTJVbYByWL0eT+KdzQOkAi48cPEOObSc9Biga7LTCcbCVPeJlYzmHDQUhzBt2jcy5BGvmZloI5SsoZvve6ug74qNq8IJMyzJzUp3kRuB0ruKIioSDi1lc783LDT3LSXyIbOGw/vHBEBY4Ax7FK8CqXJ2TsYqVsyo8QypqXDnveLcgK+PNEAhezhxC9hyV8j1I8pfF72ABE=</X509Certificate></X509Data></KeyInfo></Signature></saml:Assertion></trust:RequestedSecurityToken><trust:RequestedAttachedReference><o:SecurityTokenReference k:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" xmlns:k="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">_d8559c80-cb32-40fa-b530-7b3c9121bd27</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedAttachedReference><trust:RequestedUnattachedReference><o:SecurityTokenReference k:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" xmlns:k="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">_d8559c80-cb32-40fa-b530-7b3c9121bd27</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedUnattachedReference><trust:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</trust:TokenType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`

func TestParseResponse(t *testing.T) {
	// we'll need to change this function later, so keep a copy of it for the reset
	newTokenCopy := newToken
	Convey("Given a WS-Fed response message", t, func() {
		config := Config{}
		config.MetadataURL = "https://signin.blackbaud.com/wsfederation/metadata"
		config.MetadataCertsAreTrusted = true
		config.Realm = "http://account.blackbaud.com"
		sso := New(&config)
		Convey("When ParseResponse is called", func() {
			// change this function after signature validation, so that we can pass
			// the expiration check
			newToken = func(wresult string, realm string) (Token, error) {
				doc := etree.NewDocument()
				err := doc.ReadFromString(wresult)
				if err != nil {
					return nil, err
				}
				conditions := doc.FindElement("//Conditions")
				notOnOrAfterVal := conditions.SelectAttr("NotOnOrAfter")
				notOnOrAfterVal.Value = "3015-09-26T16:28:56.681Z"
				return &SAMLv11{XMLDoc: doc, Realm: realm}, nil
			}
			claims, err := sso.ParseResponse(wresult)
			Convey("Then a Claim is returned without error", func() {
				So(err, ShouldBeNil)
				So(claims.Subject.ID, ShouldEqual, "6ef81ad2-99f8-4c42-996c-def1d98db711")
			})
		})
		Convey("When ParseResponse is called with the wrong audience/realm combo", func() {
			// change this function after signature validation, so that we can pass
			// the expiration check
			newToken = func(wresult string, realm string) (Token, error) {
				doc := etree.NewDocument()
				err := doc.ReadFromString(wresult)
				if err != nil {
					return nil, err
				}
				conditions := doc.FindElement("//Conditions")
				notOnOrAfterVal := conditions.SelectAttr("NotOnOrAfter")
				notOnOrAfterVal.Value = "3015-09-26T16:28:56.681Z"
				return &SAMLv11{XMLDoc: doc, Realm: "http://wrongaudience.com"}, nil
			}
			_, err := sso.ParseResponse(wresult)
			Convey("Then an error should occur", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "go-wsfed: Audience check failed")
			})
		})
		Convey("When ParseResponse is called with an old response", func() {
			_, err := sso.ParseResponse(wresult)
			Convey("Then an error should occur", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "go-wsfed: Expiration check failed")
			})
		})
		Convey("When ParseResponse is called with an invalid signature response", func() {
			wresultModified := `<trust:RequestSecurityTokenResponseCollection xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><trust:RequestSecurityTokenResponse><trust:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2015-09-26T15:28:56.681Z</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2015-09-26T16:28:56.681Z</wsu:Expires></trust:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>http://account.blackbaud.com/</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><trust:RequestedSecurityToken><saml:Assertion MajorVersion="1" MinorVersion="1" AssertionID="_79b4fd7d-e0cd-406e-86a7-19ca73d360f8" Issuer="Blackbaud Authentication Service" IssueInstant="2015-09-26T15:28:56.681Z" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><saml:Conditions NotBefore="2015-09-26T15:28:56.681Z" NotOnOrAfter="2015-09-26T16:28:56.681Z"><saml:AudienceRestrictionCondition><saml:Audience>http://account.blackbaud.com/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject></saml:Subject></saml:AttributeStatement><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><Reference URI="#_79b4fd7d-e0cd-406e-86a7-19ca73d360f8"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><DigestValue>pC1Oa1rmYaYBxVW6bZJnUm7aIFHoGa1a6z0MIKVcWoc=</DigestValue></Reference></SignedInfo><SignatureValue>gQObr3Indcv1709DpW3AZUhZevHnYWGzpB6edlGh4tHpViiu6h8f1uATeIvqMxi/bttcrfQk+Rls3K8GmE7BgAXBuewKR2chObRB+CFPvnteLQOVm5DQGY4C8mEqRTJvL4LLBajw03YulFvg95WLHIzqjguTmKf4gYx++uAS7n9zuAHrQ5XF/5B1ae6PER+dJsc2vNLdxrOuJNPYJZ0L5PJhF8bmAMHcwFYd3JfgDH8dJ0rxpfXr4MVinx94Alo9U2lzWuHu/yMQ8pr8qsNllDVq0yP5J7epSq5iO6RbkN2FQjFdsjmuNstteOn/vs8xc00lhDWvttnDH65RPUtgDA==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDFzCCAgOgAwIBAgIQYyFH4hyHqIZJFSvhaTufDDAJBgUrDgMCHQUAMCAxHjAcBgNVBAMTFVRlc3RCQkF1dGhTaWduaW5nQ2VydDAeFw0xMzExMDUxNjUzNTlaFw0zOTEyMzEyMzU5NTlaMCAxHjAcBgNVBAMTFVRlc3RCQkF1dGhTaWduaW5nQ2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMyjnT+N3cypXtoTfr8HTNXcThqPKSQyioqIt0A7ZEQjByErcFdx5LyPSxyUWNg9r9Ay3T/qUqmCD4roK/LruT8W+02SLgZLGJ4cecuQqOryABVn3SeTCuViLVRFkAbGVWXqEI2woFq226xCyKEbYMIr0Lxisuo8nEQ0XSAYh2tiT6XXMf2aHomBxxUk9tkfyjBqim+OBZxglKQ+jQgA35CDi6NezJaSE13oNuo7iMlOyYV3+jPh/tohYKxhAod2biMa5oKDmVc3C6zvKZyoSVMQE0jRs2SzZW/TzBXkHfBAtoSRCarWtTv+ode+XYcQw0Hi5p5FKYmKx/sdx4RvLG0CAwEAAaNVMFMwUQYDVR0BBEowSIAQZY/UuhZiXYqsNv1VH1ec3aEiMCAxHjAcBgNVBAMTFVRlc3RCQkF1dGhTaWduaW5nQ2VydIIQYyFH4hyHqIZJFSvhaTufDDAJBgUrDgMCHQUAA4IBAQBokHC1xp2I4+K7SzGQiXehlLcjDX4+9wWX+8ZzByOKyTIfc+3DthoU1aWiuG1ioFyL8ttRLm10n3PSXR7hJtXY4JnyxfolZy+c6+n3AsYnstaZipZgnCxJ2+P1e+MzbOoMFuBceg+vpW0dJex2MrJ5h/khwFNVvhoPnGT8W7j6Q+Lw6VeexbbLBNPtpmHlrK5/7RjjZdZTvFbEMqBz1hl4Ny1Gz+mLq4fsNxC4eoW5kq/MyVbigX8kwOonr4dh68OSOLoYJ9ml62wE0uhiamM89zaFeui6e/R/xAqsTlnl10qDBDVKcGHyIrmgBUkHYknQxCnHoFW/N+w8KmhryAko</X509Certificate></X509Data></KeyInfo></Signature></saml:Assertion></trust:RequestedSecurityToken><trust:RequestedAttachedReference><o:SecurityTokenReference k:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" xmlns:k="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">_79b4fd7d-e0cd-406e-86a7-19ca73d360f8</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedAttachedReference><trust:RequestedUnattachedReference><o:SecurityTokenReference k:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1" xmlns:k="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">_79b4fd7d-e0cd-406e-86a7-19ca73d360f8</o:KeyIdentifier></o:SecurityTokenReference></trust:RequestedUnattachedReference><trust:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</trust:TokenType><trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType><trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</trust:KeyType></trust:RequestSecurityTokenResponse></trust:RequestSecurityTokenResponseCollection>`
			_, err := sso.ParseResponse(wresultModified)
			Convey("Then an error should occur", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldStartWith, "signedxml: ")
			})
		})
		Convey("When ParseResponse is called with an unsupported Token", func() {
			newToken = func(wresult string, realm string) (Token, error) {
				return nil, errors.New("fake token error")
			}
			_, err := sso.ParseResponse(wresult)
			Convey("Then an error should occur", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "fake token error")
			})
		})
		Reset(func() {
			newToken = newTokenCopy
		})
	})
}

func TestWSFedConfig(t *testing.T) {
	Convey("Given an invalid config object", t, func() {
		config := Config{}
		Convey("When a wsfed.New is called without a realm", func() {
			f := func() { New(&config) }
			Convey("Then it should panic", func() {
				So(f, ShouldPanic)
			})
		})
		Convey("When a wsfed.New is called without an endpoint", func() {
			config.Realm = "fake"
			f := func() { New(&config) }
			Convey("Then it should panic", func() {
				So(f, ShouldPanic)
			})
		})
		Convey("When a wsfed.New is called without a cert", func() {
			config.Realm = "fake"
			config.IDPEndpoint = "fake"
			f := func() { New(&config) }
			Convey("Then it should panic", func() {
				So(f, ShouldPanic)
			})
		})
	})
}
