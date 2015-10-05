package wsfed

// Claims holds the assertion data from the WS-Fed response
type Claims struct {
	Subject    Subject
	Attributes []Attribute
}

// Subject holds the unique identifier for the authenticated requestor
type Subject struct {
	ID     string
	Format string
}

// Attribute holds the names and values of the requestor's claims
type Attribute struct {
	Name   string
	Values []string
}
