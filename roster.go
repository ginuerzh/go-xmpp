// roster
package xmpp

type Roster struct {
	items []*RosterItem
}

func (roster *Roster) Type() string {
	return "roster"
}

func (roster *Roster) Add(item *RosterItem) {
	roster.items = append(roster.items, item)
}

func (roster *Roster) Items() []*RosterItem {
	return roster.items
}

func (roster *Roster) Item(jid string) *RosterItem {
	for _, item := range roster.items {
		if item.Jid == jid {
			return item
		}
	}
	return nil
}

func decodeRoster(query *rosterQuery) *Roster {
	roster := &Roster{}
	for _, item := range query.Items {
		i := &RosterItem{
			Jid:          item.Jid,
			Name:         item.Name,
			Group:        item.Group,
			Subscription: item.Subscription,
		}
		roster.Add(i)
	}
	return roster
}

type RosterItem struct {
	Jid          string
	Name         string
	Group        string
	Subscription string
}
