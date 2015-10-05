package wsfed

import (
	"errors"
	"regexp"
	"time"

	"github.com/ma314smith/etree"
)

// SAMLv11 is an implentation of the Token interface for SAML v1.1 tokens
type SAMLv11 struct {
	XMLDoc *etree.Document
	Realm  string
}

// Validate verifies that the expiration and audience are valid
func (s *SAMLv11) Validate() error {
	if s.XMLDoc == nil {
		return errors.New("go-wsfed: SAMLv11.XMLDoc is nil")
	}
	if err := s.validateExpiration(); err != nil {
		return err
	}
	if err := s.validateAudience(); err != nil {
		return err
	}
	return nil
}

func (s *SAMLv11) validateExpiration() error {
	conditions := s.XMLDoc.FindElement("//Conditions")
	if conditions == nil {
		return errors.New("go-wsfed: unable to find Conditions in SAMLv11 token")
	}

	notBeforeVal := conditions.SelectAttrValue("NotBefore", "")
	notOnOrAfterVal := conditions.SelectAttrValue("NotOnOrAfter", "")
	if notBeforeVal == "" || notOnOrAfterVal == "" {
		return errors.New("go-wsfed: unable to find Expiration attributes")
	}

	notBefore, err := parseISO8601Time(notBeforeVal)
	if err != nil {
		return errors.New("go-wsfed: unable to parse NotBefore attribute")
	}
	notOnOrAfter, err := parseISO8601Time(notOnOrAfterVal)
	if err != nil {
		return errors.New("go-wsfed: unable to parse NotOnOrAfter attribute")
	}

	nowUTC := time.Now().UTC()
	// account for clock skew
	notBefore = notBefore.Add(-1 * time.Minute)
	notOnOrAfter = notOnOrAfter.Add(1 * time.Minute)

	if nowUTC.Before(notBefore) || nowUTC.After(notOnOrAfter) {
		return errors.New("go-wsfed: Expiration check failed")
	}
	return nil
}

func (s *SAMLv11) validateAudience() error {
	audienceNode := s.XMLDoc.FindElement("//Audience")
	if audienceNode == nil {
		return errors.New("go-wsfed: unable to find Audience in SAMLv11 token")
	}

	re := regexp.MustCompile("/$")
	audience := re.ReplaceAllString(audienceNode.Text(), "")
	realm := re.ReplaceAllString(s.Realm, "")

	if audience != realm {
		return errors.New("go-wsfed: Audience check failed")
	}
	return nil
}

// GetClaims returns a Claims object populated with data from the token
func (s *SAMLv11) GetClaims() (claims Claims, err error) {
	if s.XMLDoc == nil {
		return claims, errors.New("go-wsfed: SAMLv11.XMLDoc is nil")
	}

	nameIDElem := s.XMLDoc.FindElement("//NameIdentifier")
	if nameIDElem != nil {
		claims.Subject.ID = nameIDElem.Text()
		claims.Subject.Format = nameIDElem.SelectAttrValue("Format", "")
	}

	attributeElements := s.XMLDoc.FindElements("//Attribute")
	var attributes []Attribute
	for _, ae := range attributeElements {
		valuesElements := ae.SelectElements("AttributeValue")
		var values []string
		for _, ve := range valuesElements {
			values = append(values, ve.Text())
		}

		a := Attribute{
			Name:   ae.SelectAttrValue("AttributeName", ""),
			Values: values,
		}

		attributes = append(attributes, a)
	}

	claims.Attributes = attributes
	return claims, nil
}
