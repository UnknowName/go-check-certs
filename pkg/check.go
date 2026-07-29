package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const (
	errExpiringShortly = "expires in %d hours"
	errExpiringSoon    = "expires in %d days"
	errExpired         = "SSLCertificate has expired"
)

type CheckResult struct {
	WarnMsg string
	Host    string
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

// certDomainMatches 检查证书的域名（SAN 和 CommonName）是否与目标主机匹配
// 用于排除服务端返回了不匹配域名的证书（如 CDN 配置错误导致的误报）
func certDomainMatches(host string, cert *x509.Certificate) bool {
	// 去除 host 中的端口号，只保留域名部分
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// 优先检查 SAN（Subject Alternative Names）
	for _, name := range cert.DNSNames {
		if matchDomain(host, name) {
			return true
		}
	}

	// 如果 SAN 为空，回退检查 CommonName
	if len(cert.DNSNames) == 0 {
		if matchDomain(host, cert.Subject.CommonName) {
			return true
		}
	}

	return false
}

// matchDomain 检查主机名是否与证书域名模式匹配
// 支持通配符模式（如 *.example.com 匹配 www.example.com）
func matchDomain(host, pattern string) bool {
	if host == pattern {
		return true
	}

	// 处理通配符：*.example.com 应匹配 www.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // 去掉 * 保留 .example.com
		// 主机名必须以 suffix 结尾，且主机名不能等于裸域名
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}

	return false
}

// shouldSkipHost 判断是否应跳过该主机的证书检查
// 当证书域名与目标域名不匹配时返回 true（无论证书是否过期）
// 用于防止服务端返回不匹配域名的证书时产生误报
func shouldSkipHost(host string, cert *x509.Certificate) bool {
	return !certDomainMatches(host, cert)
}

// checkCertExpiry 检查单个证书的过期状态，返回告警消息
// 只应用于叶证书（PeerCertificates[0]），避免中间/根证书的误报
// 使用四舍五入计算天数，修复整数除法 expiresIn/24 导致天数偏小的 BUG
func checkCertExpiry(cert *x509.Certificate, warnDays int) string {
	timeNow := time.Now()
	if !timeNow.AddDate(0, 0, warnDays).After(cert.NotAfter) {
		return "" // 未到期，无告警
	}

	expiresIn := cert.NotAfter.Sub(timeNow).Hours()
	if expiresIn <= 0 {
		return errExpired
	}
	if expiresIn <= 48 {
		return fmt.Sprintf(errExpiringShortly, int64(expiresIn))
	}
	// 四舍五入计算天数：71小时 ≈ 2.96天 → 3天
	days := int64(expiresIn/24 + 0.5)
	return fmt.Sprintf(errExpiringSoon, days)
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

	// 使用 InsecureSkipVerify 跳过 TLS 证书验证，
	// 以便在证书过期或域名不匹配时仍能获取到证书信息
	conf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 需要获取证书信息以手动检查域名和过期
	}
	conn, err := tls.Dial("tcp", host, conf)
	if err != nil {
		log.Println("WARN skip check", host, err)
		return
	}
	defer conn.Close()

	// 获取服务端返回的叶证书，无论证书是否过期都要检查域名匹配
	leafCert := conn.ConnectionState().PeerCertificates[0]
	if shouldSkipHost(host, leafCert) {
		log.Printf("WARN skip check %s: certificate domain mismatch (cert: %s/%v)",
			host, leafCert.Subject.CommonName, leafCert.DNSNames)
		return
	}

	// 域名匹配后，只检查叶证书的过期状态（避免中间/根证书误报）
	if msg := checkCertExpiry(leafCert, warnDays); msg != "" {
		sc.out <- CheckResult{Host: host, WarnMsg: msg}
	}
	log.Println("DEBUG end checking", host)
}
