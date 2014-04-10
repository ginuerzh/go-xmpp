// stanza
package xmpp

import (
	"encoding/xml"
	"fmt"
)

const (
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

	// Message type
	MsgNormal   = "normal"
	MsgChat     = "chat"
	MsgGrpChat  = "groupchat"
	MsgHeadline = "headline"

	// stanza error type
	errorCancel = "cancel"
	errorCont   = "continue"
	errorModify = "modify"
	errorAuth   = "auth"
	errorWait   = "wait"
)

type Stanza interface {
	Type() string
	Error() *StanzaError
	encode() elementer
	decode(elementer)
}

type StanzaError struct {
	Code   string
	Type   string
	Reason string
	Text   string
}

func (e StanzaError) Error() string {
	return fmt.Sprintf("%s: %s %s", e.Code, e.Reason, e.Text)
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

func (e stanError) decode() *StanzaError {
	return &StanzaError{
		Code:   e.Code,
		Type:   e.Type,
		Reason: e.Cond.Local,
		Text:   e.Text,
	}
}

type stanIQ struct {
	XMLName xml.Name `xml:"iq"`
	stanza
	Bind       *bindBind
	Session    *session
	Roster     *rosterQuery
	DiscoItems *discoItemsQuery
	DiscoInfo  *discoInfoQuery
	Ping       *string `xml:"urn:xmpp:ping ping"`
}

func (iq stanIQ) Name() string {
	return "iq"
}

type rosterQuery struct {
	XMLName xml.Name     `xml:"jabber:iq:roster query"`
	Ver     string       `xml:"ver,attr,omitempty"`
	Items   []*queryItem `xml:"item"`
}

func (q *rosterQuery) Name() string {
	return "roster-query"
}

type discoItemsQuery struct {
	XMLName xml.Name     `xml:"http://jabber.org/protocol/disco#items query"`
	Ver     string       `xml:"ver,attr,omitempty"`
	Node    string       `xml:"node,attr,omitempty"`
	Items   []*queryItem `xml:"item"`
}

func (q *discoItemsQuery) Name() string {
	return "disco-items-query"
}

type discoInfoQuery struct {
	XMLName    xml.Name             `xml:"http://jabber.org/protocol/disco#info query"`
	Ver        string               `xml:"ver,attr,omitempty"`
	Identities []*discoInfoIdentity `xml:"identity"`
	Features   []*discoInfoFeature  `xml:"feature"`
}

func (q *discoInfoQuery) Name() string {
	return "disco-info-query"
}

type queryItem struct {
	XMLName      xml.Name `xml:"item"`
	Jid          string   `xml:"jid,attr,omitempty"`
	Node         string   `xml:"node,attr,omitempty"`
	Name         string   `xml:"name,attr,omitempty"`
	Subscription string   `xml:"subscription,attr,omitempty"`
	Approved     bool     `xml:"approved,attr,omitempty"`
	Ask          string   `xml:"ask,attr,omitempty"`
	Group        []string `xml:"group,omitempty"`
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

// XEP-0115: entity capabilities
type entityCaps struct {
	XMLName xml.Name `xml:"http://jabber.org/protocol/caps c"`
	Hash    string   `xml:"hash,attr"`
	Node    string   `xml:"node,attr"`
	Ver     string   `xml:"ver,attr"`
	Ext     string   `xml:"ext,attr"`
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

type stanMessage struct {
	XMLName xml.Name `xml:"message"`
	stanza
	Body    []*msgBody    `xml:"body"`
	Subject []*msgSubject `xml:"subject"`
	Thread  *msgThread

	Active    *string `xml:"http://jabber.org/protocol/chatstates active"`
	Composing *string `xml:"http://jabber.org/protocol/chatstates composing"`
	Paused    *string `xml:"http://jabber.org/protocol/chatstates paused"`
	Gone      *string `xml:"http://jabber.org/protocol/chatstates gone"`
}

func (msg *stanMessage) Name() string {
	return "message"
}

type msgBody struct {
	XMLName xml.Name `xml:"body"`
	Lang    string   `xml:"lang,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type msgSubject struct {
	XMLName xml.Name `xml:"subject"`
	Lang    string   `xml:"lang,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

type msgThread struct {
	XMLName xml.Name `xml:"thread"`
	Parent  string   `xml:"parent,attr,omitempty"`
	Value   string   `xml:",chardata"`
}
