// message
package xmpp

import (
	"time"
)

type Message struct {
	From      string
	To        string
	Body      string
	Subject   string
	TimeStamp time.Time
	err       *StanzaError
}

func NewMessage(to string, body string, subject string) *Message {
	return &Message{
		To:      to,
		Body:    body,
		Subject: subject,
	}
}

func (msg *Message) Type() string {
	return "message"
}

func (msg *Message) Error() *StanzaError {
	return msg.err
}

func (msg *Message) encode() elementer {
	stanMsg := &stanMessage{}
	stanMsg.To = msg.To
	stanMsg.T = MsgChat
	if len(msg.Body) > 0 {
		stanMsg.Body = make([]*msgBody, 1)
		stanMsg.Body[0] = &msgBody{Value: msg.Body}
	}
	if len(msg.Subject) > 0 {
		stanMsg.Subject = make([]*msgSubject, 1)
		stanMsg.Subject[0] = &msgSubject{Value: msg.Subject}
	}

	return stanMsg
}

func (msg *Message) decode(e elementer) {
	stanMsg := e.(*stanMessage)

	if stanMsg.Err != nil {
		msg.err = stanMsg.Err.decode()
		return
	}

	msg.From = stanMsg.From
	msg.To = stanMsg.To
	if len(stanMsg.Body) > 0 {
		msg.Body = stanMsg.Body[0].Value
	}
	if len(stanMsg.Subject) > 0 {
		msg.Subject = stanMsg.Subject[0].Value
	}
}

type ChatState struct {
	Jid   string
	State string
	err   *StanzaError
}

func (state ChatState) Type() string {
	return "message:state"
}

func (state ChatState) Error() *StanzaError {
	return state.err
}

func (state *ChatState) decode(e elementer) {
	msg := e.(*stanMessage)

	if msg.Err != nil {
		state.err = msg.Err.decode()
		return
	}

	if msg.Active != nil {
		state.State = "active"
	} else if msg.Composing != nil {
		state.State = "composing"
	} else if msg.Paused != nil {
		state.State = "paused"
	} else if msg.Gone != nil {
		state.State = "gone"
	}
}

func (state *ChatState) encode() elementer {
	return nil
}
