// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)


const (
	errExpiringShortly = "%s: ** expires in %d hours! **"
	errExpiringSoon    = "%s  expires in roughly %d days."
	errSunsetAlg       = "%s  expires after the sunset date for its signature algorithm '%s'."
	contentType = "application/json"
)

type sigAlgSunset struct {
	name      string    // Human readable name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

// sunsetSigAlgs is an algorithm to string mapping for signature algorithms
// which have been or are being deprecated.  See the following links to learn
// more about SHA1's inclusion on this list.
//
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSigAlgs = map[x509.SignatureAlgorithm]sigAlgSunset{
	x509.MD2WithRSA: {
		name:      "MD2 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.MD5WithRSA: {
		name:      "MD5 with RSA",
		sunsetsAt: time.Now(),
	},
	x509.SHA1WithRSA: {
		name:      "SHA1 with RSA",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: {
		name:      "DSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: {
		name:      "ECDSA with SHA1",
		sunsetsAt: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}

var (
	hostsFile   = flag.String("hosts", "", "The path to the file containing a list of hosts to check.")
	warnYears   = flag.Int("years", 0, "Warn if the certificate will expire within this many years.")
	warnMonths  = flag.Int("months", 0, "Warn if the certificate will expire within this many months.")
	warnDays    = flag.Int("days", 0, "Warn if the certificate will expire within this many days.")
	checkSigAlg = flag.Bool("check-sig-alg", true, "Verify that non-root certificates are using a good signature algorithm.")
	ddToken     = flag.String("token", "", "the url of dding")
)

type TMessage struct {
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

func NewTMessage(msg string, atMobiles []string, atAll bool) *TMessage {
	if atMobiles == nil {
		atMobiles = make([]string, 0)
	}
	atUsers := At{AtMobiles: atMobiles}
	text := Content{Content: msg}
	return &TMessage{
		MsgType: "text",
		Text:    text,
		At:      atUsers,
		IsAtAll: atAll,
	}
}

func (tm *TMessage) Encode() []byte {
	_bytes, err := json.Marshal(&tm)
	if err != nil {
		return nil
	}
	return _bytes
}

func main() {
	flag.Parse()
	if len(*hostsFile) == 0 {
		flag.Usage()
		return
	}
	if *warnYears < 0 {
		*warnYears = 0
	}
	if *warnMonths < 0 {
		*warnMonths = 0
	}
	if *warnDays < 0 {
		*warnDays = 0
	}
	if *warnYears == 0 && *warnMonths == 0 && *warnDays == 0 {
		*warnDays = 30
	}
	if ddToken == nil || *ddToken == "" {
		log.Println("dding token isn't set, notifying will be disable")
	}
	for {
		processHosts()
		log.Println("Sleeping 24 hours....")
		time.Sleep(time.Hour * 24)
	}
}

func processHosts() {
	fileContents, err := os.ReadFile(*hostsFile)
	if err != nil {
		return
	}
	lines := strings.Split(string(fileContents), "\n")
	msgs := make([]string, 0)
	for _, line := range lines {
		host := strings.TrimSpace(line)
		if len(host) == 0 || host[0] == '#' {
			continue
		}
		msg := checkHost(host)
		if msg != nil {
			msg := strings.TrimSpace(*msg)
			if msg == "" {
				continue
			}
			msgs = append(msgs, msg)
		}
	}
	fullMsg := strings.Join(msgs, "\n")
	log.Println("send notifying message\n", fullMsg)
	if len(*ddToken) > 0 {
		msg := NewTMessage(fullMsg, nil, false)
		httpClient := http.Client{Timeout: time.Second * 5}
		_, err := httpClient.Post(*ddToken, contentType, bytes.NewBuffer(msg.Encode()))
		if err != nil {
			log.Println(string(msg.Encode()), "发送到钉钉失败", err)
		}
	}
}

func checkHost(host string)  *string {
	result := new(string)
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		return nil
	}
	defer conn.Close()
	timeNow := time.Now()
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			// Check the expiration.
			if timeNow.AddDate(*warnYears, *warnMonths, *warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				if expiresIn <= 48 {
					*result = fmt.Sprintf(errExpiringShortly, host, expiresIn)
				} else {
					*result = fmt.Sprintf(errExpiringSoon, host, expiresIn/24)
				}
			}
			// Check the signature algorithm, ignoring the root certificate.
			if alg, exists := sunsetSigAlgs[cert.SignatureAlgorithm]; *checkSigAlg && exists && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					*result =  fmt.Sprintf(errSunsetAlg, host, alg.name)
				}
			}
		}
	}
	return result
}
