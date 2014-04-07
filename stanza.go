// stanza
package xmpp

import (
	"encoding/xml"
	"fmt"
)

const (
	StanError = "error"

	// IQ type
	IQGet    = "get"
	IQSet    = "set"
	IQResult = "result"

	// Presence type
	PresenceUnavailable  = "unavailable"
	PresenceSubscribe    = "subscribe"
	PresenceSubscribed   = "subscribed"
	PresenceUnsubscribe  = "unsubscribe"
	PresenceUnsubscribed = "unsubscribed"
	PresenceProbe        = "probe"

	StatusChat = "chat"
	StatusAway = "away"
	StatusXa   = "xa"
	StatusDnd  = "dnd"

	errorCancel = "cancel"
	errorCont   = "continue"
	errorModify = "modify"
	errorAuth   = "auth"
	errorWait   = "wait"
)

type Stanzar interface {
	Type() string
	Encode() []byte
}

type stanza struct {
	Id   string `xml:"id,attr,omitempty"`
	T    string `xml:"type,attr,omitempty"`
	From string `xml:"from,attr,omitempty"`
	To   string `xml:"to,attr,omitempty"`
	Lang string `xml:"lang,attr,omitempty"`
	Err  *stanError
}

type stanError struct {
	XMLName xml.Name `xml:"jabber:client error"`
	Code    string   `xml:"code,attr"`
	Type    string   `xml:"type,attr"`
	Cond    xml.Name `xml:",any"`
	Text    string   `xml:"text,omitempty"`
}

func (e stanError) Error() string {
	return fmt.Sprintf("%s(%s): %s", e.Type, e.Code, e.Cond.Local)
}

type stanIQ struct {
	XMLName xml.Name `xml:"iq"`
	stanza
	Bind       *bindBind
	Roster     *rosterQuery
	DiscoItems *discoItemsQuery
	DiscoInfo  *discoInfoQuery
}

func (iq stanIQ) Name() string {
	return "iq"
}

type rosterQuery struct {
	XMLName xml.Name     `xml:"jabber:iq:roster query"`
	Items   []*queryItem `xml:"item"`
}

type discoItemsQuery struct {
	XMLName xml.Name     `xml:"http://jabber.org/protocol/disco#items query"`
	Items   []*queryItem `xml:"item"`
}

type discoInfoQuery struct {
	XMLName  xml.Name `xml:"http://jabber.org/protocol/disco#info query"`
	Identity *discoInfoIdentity
	features []*discoInfoFeature
}

type queryItem struct {
	XMLName      xml.Name `xml:"item"`
	Jid          string   `xml:"jid,attr,omitempty"`
	Name         string   `xml:"name,attr,omitempty"`
	Subscription string   `xml:"subscription,attr,omitempty"`
	Group        string   `xml:"group,omitempty"`
}

type discoInfoIdentity struct {
	XMLName  xml.Name `xml:"identity"`
	Category string   `xml:"category,attr"`
	Type     string   `xml:"type,attr"`
	Name     string   `xml:"name,attr"`
}

type discoInfoFeature struct {
	XMLName xml.Name `xml:"feature"`
	Var     string   `xml:"var,attr"`
}

type stanPresence struct {
	XMLName xml.Name `xml:"presence"`
	stanza
	Show     string `xml:"show,omitempty"`
	Status   string `xml:"status,omitempty"`
	Priority int    `xml:"priority,omitempty"`
}

func (p stanPresence) Name() string {
	return "presence"
}
