package wsfed

import (
	"errors"

	"github.com/ma314smith/etree"
)

// Token abstracts the different assertions available for WS-Fed
type Token interface {
	Validate() error
	GetClaims() (Claims, error)
}

// newToken pareses the assertion from a wresult string and returns the
// corresponding token type
var newToken = func(wresult string, realm string) (Token, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(wresult)
	if err != nil {
		return nil, err
	}

	assertion := doc.FindElement("//Assertion")
	if assertion == nil {
		return nil, errors.New("go-wsfed: unable to find Assertion element")
	}

	majorVersion := assertion.SelectAttrValue("MajorVersion", "")
	minorVersion := assertion.SelectAttrValue("MinorVersion", "")

	switch {
	case majorVersion == "1" && minorVersion == "1":
		return &SAMLv11{XMLDoc: doc, Realm: realm}, nil
	default:
		return nil, errors.New("go-wsfed: unsupported token")
	}
}
