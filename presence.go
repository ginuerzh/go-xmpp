// presence
package xmpp

import ()

type Presence struct {
	Types  string
	Jid    string
	Show   string
	Status string
	err    *StanzaError
}

func (p *Presence) Type() string {
	return "presence"
}

func (p *Presence) Error() *StanzaError {
	return p.err
}

func (p *Presence) decode(e elementer) {
	sp := e.(*stanPresence)

	if sp.Err != nil {
		p.err = sp.Err.decode()
		return
	}

	p.Types = sp.T
	p.Jid = sp.From
	p.Show = sp.Show
	p.Status = sp.Status
}

func (p *Presence) encode() elementer {
	sp := &stanPresence{}
	sp.T = p.Types
	sp.To = p.Jid
	sp.Show = p.Show
	sp.Status = p.Status

	return sp
}
