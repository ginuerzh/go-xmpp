// presence
package xmpp

import (
	"encoding/xml"
)

type Presence struct {
	Types  string
	Jid    string
	Show   string
	Status string
}

func (p *Presence) Type() string {
	return "presence"
}

func (p *Presence) decode(sp *stanPresence) {
	p.Types = sp.T
	p.Jid = sp.From
	p.Show = sp.Show
	p.Status = sp.Status
}

func (p *Presence) Encode() []byte {
	sp := &stanPresence{}
	sp.T = p.Types
	sp.To = p.Jid
	sp.Show = p.Show
	sp.Status = p.Status

	b, _ := xml.Marshal(sp)
	return b
}
