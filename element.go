// element
package xmpp

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const (
	nsStream = "http://etherx.jabber.org/streams"
	nsTLS    = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL   = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind   = "urn:ietf:params:xml:ns:xmpp-bind"
	nsClient = "jabber:client"
)

const (
	mechanPlain = "PLAIN"
	mechanMd5   = "DIGEST-MD5"
)

const (
	IQGet    = "get"
	IQSet    = "set"
	IQResult = "result"
	IQError  = "error"
)

type Elementer interface {
	String() string
}

type streamElem struct {
	domain string
}

func (s streamElem) String() string {
	b := new(bytes.Buffer)
	xml.EscapeText(b, []byte(s.domain))

	return fmt.Sprintf(xml.Header+
		"<stream:stream to='%s' xmlns='%s'"+
		" xmlns:stream='%s' version='1.0'>",
		b.String(), nsClient, nsStream)
}

type iqAuth struct {
	XMLName xml.Name `xml:"http://jabber.org/features/iq-auth auth"`
}

type iqRegister struct {
	XMLName xml.Name `xml:"http://jabber.org/features/iq-register register"`
}

// RFC 3920  C.1  Streams name space
type streamFeatures struct {
	XMLName    xml.Name `xml:"http://etherx.jabber.org/streams features"`
	StartTLS   tlsStartTLS
	Mechanisms saslMechanisms
	Compress   compression
	Bind       bindBind
	Session    session
	Auth       iqAuth
	Register   iqRegister
}

type streamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name
	Text    string
}

// RFC 3920  C.3  TLS name space

type tlsStartTLS struct {
	XMLName  xml.Name `xml:":ietf:params:xml:ns:xmpp-tls starttls"`
	Required bool
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

// RFC 3920  C.4  SASL name space

type saslMechanisms struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanism []string `xml:"mechanism"`
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
	Value     string   `xml:",chardata"`
}

func (sa saslAuth) String() string {
	b, _ := xml.Marshal(sa)
	return string(b)
}

type saslChallenge struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl challenge"`
	Value   string   `xml:",chardata"`
}

type saslResponse struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl response"`
	Value   string   `xml:",chardata"`
}

func (sr saslResponse) String() string {
	b, _ := xml.Marshal(sr)
	return string(b)
}

type saslRspAuth string

type saslAbort struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

type saslSuccess struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl success"`
	Value   string   `xml:",chardata"`
}

func (ss saslSuccess) String() string {
	b, _ := xml.Marshal(ss)
	return string(b)
}

type saslFailure struct {
	Name xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Any  xml.Name
}

// RFC 3920  C.5  Resource binding name space

type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource,omitempty"`
	Jid      string   `xml:"jid,omitempty"`
}

func (bind bindBind) String() string {
	b, _ := xml.Marshal(bind)
	return string(b)
}

type session struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-session session"`
}

type compression struct {
	XMLName xml.Name `xml:"http://jabber.org/features/compress compression"`
	Method  string   `xml:"method"`
}

// RFC 3921  B.1  jabber:client

type Stanza struct {
	Id   string `xml:"id,attr,omitempty"`
	Type string `xml:"type,attr"`
	From string `xml:"from,attr,omitempty"`
	To   string `xml:"to,attr,omitempty"`

	SubElem interface{}
}

type IQ struct {
	XMLName xml.Name `xml:"iq"`
	Stanza
}

func NewIQ(t string, to string) *IQ {
	return &IQ{
		Stanza: Stanza{
			Type: t,
			To:   to,
		},
	}
}

func (iq *IQ) SetElem(elem Elementer) {
	iq.SubElem = elem
}

func (iq IQ) String() string {
	b, _ := xml.Marshal(iq)
	return string(b)
}

type clientMessage struct {
	XMLName xml.Name `xml:"jabber:client message"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // chat, error, groupchat, headline, or normal

	// These should technically be []clientText,
	// but string is much more convenient.
	Subject string `xml:"subject"`
	Body    string `xml:"body"`
	Thread  string `xml:"thread"`

	// Any hasn't matched element
	Other []string `xml:",any"`
}

type clientText struct {
	Lang string `xml:",attr"`
	Body string `xml:"chardata"`
}

type clientPresence struct {
	XMLName xml.Name `xml:"jabber:client presence"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // error, probe, subscribe, subscribed, unavailable, unsubscribe, unsubscribed
	Lang    string   `xml:"lang,attr"`

	Show     string `xml:"show"`        // away, chat, dnd, xa
	Status   string `xml:"status,attr"` // sb []clientText
	Priority string `xml:"priority,attr"`
	Error    *clientError
}

type clientIQ struct { // info/query
	XMLName xml.Name `xml:"jabber:client iq"`
	From    string   `xml:",attr"`
	Id      string   `xml:",attr"`
	To      string   `xml:",attr"`
	Type    string   `xml:",attr"` // error, get, result, set
	Error   clientError
	Bind    bindBind
}

type clientError struct {
	XMLName xml.Name `xml:"jabber:client error"`
	Code    string   `xml:",attr"`
	Type    string   `xml:",attr"`
	Any     xml.Name
	Text    string
}
