// element
package xmpp

import (
	//"bytes"
	"encoding/xml"
	//"fmt"
)

const (
	nsStream = "http://etherx.jabber.org/streams"
	nsTLS    = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL   = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind   = "urn:ietf:params:xml:ns:xmpp-bind"
	nsStanza = "urn:ietf:params:xml:ns:xmpp-stanzas"
	nsClient = "jabber:client"
	nsRoster = "jabber:iq:roster"
)

const (
	mechanPlain = "PLAIN"
	mechanMd5   = "DIGEST-MD5"
)

type elementer interface {
	Name() string
}

type xmppStream struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams stream"`
	NS      string   `xml:",attr"`
	Id      string   `xml:"id,attr,omitempty"`
	From    string   `xml:"from,attr,omitempty"`
	To      string   `xml:"to,attr,omitempty"`
	Version string   `xml:"version,attr"`
}

func streamElement(domain string) []byte {
	return []byte("<stream:stream " +
		"xmlns='jabber:client' " +
		"xmlns:stream='http://etherx.jabber.org/streams' " +
		"version='1.0' " +
		" to='" + domain + "'>")
}

func (s xmppStream) Name() string {
	return "stream"
}

/*
func (s xmppStream) String() string {
	b := new(bytes.Buffer)
	xml.EscapeText(b, []byte(s.To))

	return fmt.Sprintf(xml.Header+
		"<stream:stream to='%s' xmlns='%s'"+
		" xmlns:stream='%s' version='1.0'>",
		b.String(), nsClient, nsStream)
}
*/
type iqAuth struct {
	XMLName xml.Name `xml:"http://jabber.org/features/iq-auth auth"`
}

type iqRegister struct {
	XMLName xml.Name `xml:"http://jabber.org/features/iq-register register"`
}

// RFC 3920  C.1  Streams name space
type streamFeatures struct {
	XMLName    xml.Name `xml:"http://etherx.jabber.org/streams features"`
	StartTLS   *tlsStartTLS
	Mechanisms *saslMechanisms
	Compress   *compression
	Bind       *bindBind
	Session    *session
	Auth       *iqAuth
	Register   *iqRegister
}

func (e streamFeatures) Name() string {
	return "stream-eatures"
}

type streamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name
	Text    string
}

func (e streamError) Name() string {
	return "stream-error"
}

// RFC 3920  C.3  TLS name space

type tlsStartTLS struct {
	XMLName xml.Name  `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`
	Any     *xml.Name `xml:",any"`
}

func (e tlsStartTLS) Required() bool {
	return e.Any != nil && e.Any.Local == "required"
}

func (e tlsStartTLS) Name() string {
	return "tls-starttls"
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

func (e tlsProceed) Name() string {
	return "tls-proceed"
}

type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

func (e tlsFailure) Name() string {
	return "tls-failure"
}

func (e tlsFailure) Error() string {
	return "tls failure"
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

func (e saslAuth) Name() string {
	return "sasl-auth"
}

type saslChallenge struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl challenge"`
	Value   string   `xml:",chardata"`
}

func (e saslChallenge) Name() string {
	return "sasl-challenge"
}

type saslResponse struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl response"`
	Value   string   `xml:",chardata"`
}

func (e saslResponse) Name() string {
	return "sasl-response"
}

type saslAbort struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

func (e saslAbort) Name() string {
	return "sasl-abort"
}

func (e saslAbort) Error() string {
	return "abort"
}

type saslSuccess struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl success"`
	Value   string   `xml:",chardata"`
}

func (e saslSuccess) Name() string {
	return "sasl-success"
}

type saslFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Any     xml.Name `xml:",any"`
}

func (e saslFailure) Name() string {
	return "sasl-failure"
}

func (e saslFailure) Error() string {
	return e.Any.Local
}

// RFC 3920  C.5  Resource binding name space

type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource,omitempty"`
	Jid      string   `xml:"jid,omitempty"`
}

func (e bindBind) Name() string {
	return "bind"
}

type session struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-session session"`
}

type compression struct {
	XMLName xml.Name `xml:"http://jabber.org/features/compress compression"`
	Method  string   `xml:"method"`
}

// RFC 3921  B.1  jabber:client

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
	Error    *stanError
}
