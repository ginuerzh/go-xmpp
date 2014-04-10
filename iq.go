// iq
package xmpp

import ()

type QueryItem struct {
	Jid          string
	Name         string
	Node         string
	Subscription string
	Group        []string
}

type IQRoster struct {
	items []*QueryItem
	err   *StanzaError
}

func (roster *IQRoster) Type() string {
	return "iq:roster"
}

func (roster *IQRoster) Error() *StanzaError {
	return roster.err
}

func (roster *IQRoster) Add(item *QueryItem) {
	roster.items = append(roster.items, item)
}

func (roster *IQRoster) Items() []*QueryItem {
	return roster.items
}

func (roster *IQRoster) Item(jid string) *QueryItem {
	for _, item := range roster.items {
		if item.Jid == jid {
			return item
		}
	}
	return nil
}

func (roster *IQRoster) decode(e elementer) {
	st := e.(*stanIQ)

	if st.Err != nil {
		roster.err = st.Err.decode()
		return
	}

	for _, item := range st.Roster.Items {
		i := &QueryItem{
			Jid:          item.Jid,
			Name:         item.Name,
			Group:        item.Group,
			Subscription: item.Subscription,
		}
		roster.Add(i)
	}
}

func (roster *IQRoster) encode() elementer {
	query := &rosterQuery{}
	for _, item := range roster.items {
		qi := &queryItem{
			Jid:          item.Jid,
			Name:         item.Name,
			Group:        item.Group,
			Subscription: item.Subscription,
		}
		query.Items = append(query.Items, qi)
	}

	st := &stanIQ{}
	if query.Items == nil {
		st.T = "get"
	} else {
		st.T = "set"
	}

	st.Roster = query

	return st
}

type IQDiscoInfo struct {
	Features   []string
	Identities []*Identity
	err        *StanzaError
}

type Identity struct {
	Category string
	Type     string
	Name     string
}

func (disco *IQDiscoInfo) Type() string {
	return "iq:disco:info"
}

func (disco *IQDiscoInfo) Error() *StanzaError {
	return disco.err
}

func (disco *IQDiscoInfo) decode(e elementer) {
	st := e.(*stanIQ)

	if st.Err != nil {
		disco.err = st.Err.decode()
		return
	}

	for _, id := range st.DiscoInfo.Identities {
		disco.Identities = append(disco.Identities,
			&Identity{Category: id.Category, Type: id.Type, Name: id.Name})
	}

	for _, f := range st.DiscoInfo.Features {
		disco.Features = append(disco.Features, f.Var)
	}
}

func (disco *IQDiscoInfo) encode() elementer {
	query := &discoInfoQuery{}

	/*
		for _, id := range disco.Identities {
			query.Identities = append(query.Identities,
				&discoInfoIdentity{Category: id.Category, Type: id.Type, Name: id.Name})
		}

		for _, f := range disco.Features {
			query.Features = append(query.Features,
				&discoInfoFeature{Var: f})
		}
	*/

	st := &stanIQ{}
	st.T = "get"
	st.DiscoInfo = query

	return st
}

type IQDiscoItems struct {
	Node  string
	Items []*QueryItem
	err   *StanzaError
}

func (disco *IQDiscoItems) Type() string {
	return "iq:disco:items"
}

func (disco *IQDiscoItems) Error() *StanzaError {
	return disco.err
}

func (disco *IQDiscoItems) decode(e elementer) {
	st := e.(*stanIQ)
	if st.Err != nil {
		disco.err = st.Err.decode()
		return
	}

	disco.Node = st.DiscoItems.Node

	for _, item := range st.DiscoItems.Items {
		i := &QueryItem{
			Jid:          item.Jid,
			Name:         item.Name,
			Node:         item.Node,
			Group:        item.Group,
			Subscription: item.Subscription,
		}
		disco.Items = append(disco.Items, i)
	}
}

func (disco *IQDiscoItems) encode() elementer {
	st := &stanIQ{}
	st.T = "get"
	st.DiscoItems = &discoItemsQuery{}

	return st
}
