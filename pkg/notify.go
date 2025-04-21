package pkg

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	contentType    = "application/json"
	defaultTimeout = time.Second * 5
)

func NewNotify(config *NotifyConfig, in <-chan CheckResult) Notifier {
	switch config.Type {
	case "dding":
		return &DDingNotify{
			ch:  in,
			url: config.Get("url"),
		}
	}
	return nil
}

type Notifier interface {
	Send(waitTime time.Duration)
}

type DDingNotify struct {
	ch  <-chan CheckResult
	url string
}

func (dn *DDingNotify) Send(waitTime time.Duration) {
	ticker := time.NewTicker(waitTime)
	msgs := make(map[string][]string, 0)
	for {
		select {
		case msg := <-dn.ch:
			msgs[msg.WarnMsg] = append(msgs[msg.WarnMsg], msg.Host)
		case <-ticker.C:
			if len(msgs) == 0 {
				log.Println("DEBUG no messages need to send")
				continue
			}
			httpClient := http.Client{Timeout: defaultTimeout}
			sendMsgs := make([]string, 0)
			for msg, hosts := range msgs {
				sendMsgs = append(sendMsgs, msg)
				sendMsgs = append(sendMsgs, hosts...)
			}
			msg := newDMessage(strings.Join(sendMsgs, "\n"), nil, false)
			resp, err := httpClient.Post(dn.url, contentType, bytes.NewBuffer(msg.Encode()))
			if err != nil {
				log.Println("ERROR DDing Notify send failed", err)
			} else {
				_re, _ := io.ReadAll(resp.Body)
				log.Println("DEBUG dding response", string(_re))
			}
			msgs = make(map[string][]string, 0)
		}
	}
}

type DMessage struct {
	MsgType string  `json:"msgtype"`
	Text    Content `json:"text"`
	At      At      `json:"at"`
	IsAtAll bool    `json:"isAtAll"`
}

type Content struct {
	Content string `json:"content"`
}

type At struct {
	AtMobiles []string `json:"atMobiles"`
}

func newDMessage(msg string, atMobiles []string, atAll bool) *DMessage {
	if atMobiles == nil {
		atMobiles = make([]string, 0)
	}
	atUsers := At{AtMobiles: atMobiles}
	text := Content{Content: msg}
	return &DMessage{
		MsgType: "text",
		Text:    text,
		At:      atUsers,
		IsAtAll: atAll,
	}
}

func (tm *DMessage) Encode() []byte {
	data, err := json.Marshal(&tm)
	if err != nil {
		return nil
	}
	return data
}
