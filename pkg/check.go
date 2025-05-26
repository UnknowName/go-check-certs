package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	errExpiringShortly = "expires in %d hours"
	errExpiringSoon    = "expires in %d days"
	errSunsetAlg       = "expires after the sunset date for its signature algorithm '%s'."
	errExpired         = "SSLCertificate has expired"
)

type CheckResult struct {
	WarnMsg string
	Host    string
}

type sigAlgSunset struct {
	name      string    // Human read name of signature algorithm
	sunsetsAt time.Time // Time the algorithm will be sunset
}

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

type HTTPSChecker interface {
	Check(warnDays int)
}

func NewSimpleCheck(in <-chan string, out chan<- CheckResult) *SimpleCheck {
	return &SimpleCheck{
		in:  in,
		out: out,
	}
}

type SimpleCheck struct {
	in  <-chan string
	out chan<- CheckResult
}

func (sc *SimpleCheck) Check(warnDays int) {
	go func() {
		for host := range sc.in {
			go sc.checkHostHttps(host, warnDays)
		}
	}()
}

func (sc *SimpleCheck) checkHostHttps(host string, warnDays int) {
	if host == "" || host[0] == '@' {
		return
	}
	values := strings.Split(host, ":")
	if len(values) == 1 {
		host = fmt.Sprintf("%s:443", host)
	}
	if host[0] == '*' {
		// *为泛域名解析，需要指定一个字符串来替换它
		host = fmt.Sprintf("%s%s:443", "abcdefzhki", host[1:])
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		if strings.Contains(err.Error(), "certificate has expired") {
			sc.out <- CheckResult{Host: host, WarnMsg: errExpired}
		} else {
			log.Println("WARN skip check", host, err)
		}
		return
	}
	defer conn.Close()
	timeNow := time.Now()
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for certNum, cert := range chain {
			// Check the expiration.
			if timeNow.AddDate(0, 0, warnDays).After(cert.NotAfter) {
				expiresIn := int64(cert.NotAfter.Sub(timeNow).Hours())
				if expiresIn <= 48 {
					sc.out <- CheckResult{Host: host, WarnMsg: fmt.Sprintf(errExpiringShortly, expiresIn)}
				} else {
					sc.out <- CheckResult{Host: host, WarnMsg: fmt.Sprintf(errExpiringSoon, expiresIn/24)}
				}
			}
			// Check the signature algorithm, ignoring the root certificate.
			if alg, ok := sunsetSigAlgs[cert.SignatureAlgorithm]; ok && certNum != len(chain)-1 {
				if cert.NotAfter.Equal(alg.sunsetsAt) || cert.NotAfter.After(alg.sunsetsAt) {
					sc.out <- CheckResult{WarnMsg: fmt.Sprintf(errSunsetAlg, alg.name), Host: host}
				}
			}
		}
	}
	log.Println("DEBUG end checking", host)
}
