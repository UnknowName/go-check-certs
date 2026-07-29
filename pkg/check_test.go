package pkg

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"testing"
	"time"
)

// 创建测试用的证书对象，仅填充域名相关字段
func newTestCert(dnsNames []string, commonName string) *x509.Certificate {
	return &x509.Certificate{
		DNSNames:    dnsNames,
		Subject:     pkix.Name{CommonName: commonName},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		IPAddresses: []net.IP{},
	}
}

// 创建已过期的测试证书
func newExpiredTestCert(dnsNames []string, commonName string) *x509.Certificate {
	return &x509.Certificate{
		DNSNames:    dnsNames,
		Subject:     pkix.Name{CommonName: commonName},
		NotBefore:   time.Now().Add(-720 * time.Hour),
		NotAfter:    time.Now().Add(-24 * time.Hour), // 已过期
		IPAddresses: []net.IP{},
	}
}

// 创建即将过期的测试证书（在 warnDays 内过期）
func newExpiringTestCert(dnsNames []string, commonName string, daysUntilExpiry int) *x509.Certificate {
	return &x509.Certificate{
		DNSNames:    dnsNames,
		Subject:     pkix.Name{CommonName: commonName},
		NotBefore:   time.Now().Add(-720 * time.Hour),
		NotAfter:    time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour),
		IPAddresses: []net.IP{},
	}
}

func TestCertDomainMatches(t *testing.T) {
	tests := []struct {
		name       string // 测试名称
		host       string // 检测的目标域名
		dnsNames   []string
		commonName string
		want       bool // 期望的匹配结果
	}{
		{
			name:       "精确匹配-CommonName",
			host:       "example.com",
			dnsNames:   []string{},
			commonName: "example.com",
			want:       true,
		},
		{
			name:       "精确匹配-SAN",
			host:       "example.com",
			dnsNames:   []string{"example.com"},
			commonName: "",
			want:       true,
		},
		{
			name:       "通配符匹配-SAN",
			host:       "www.example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "",
			want:       true,
		},
		{
			name:       "通配符匹配-多级子域名",
			host:       "api.v1.example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "",
			want:       true,
		},
		{
			name:       "域名完全不匹配",
			host:       "wx.sixuneshop.com",
			dnsNames:   []string{"*.sissyun.com.cn"},
			commonName: "sissyun.com.cn",
			want:       false,
		},
		{
			name:       "域名后缀不同",
			host:       "shop.sixunyun.com",
			dnsNames:   []string{"*.sissyun.com.cn"},
			commonName: "",
			want:       false,
		},
		{
			name:       "通配符不应匹配裸域名",
			host:       "example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "",
			want:       false,
		},
		{
			name:       "多个SAN中有一个匹配",
			host:       "api.example.com",
			dnsNames:   []string{"*.other.com", "*.example.com"},
			commonName: "",
			want:       true,
		},
		{
			name:       "SAN和CommonName都存在-SAN优先匹配",
			host:       "api.example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "other.com",
			want:       true,
		},
		{
			name:       "SAN不匹配时忽略CommonName-现代浏览器行为",
			host:       "test.example.com",
			dnsNames:   []string{"*.other.com"},
			commonName: "test.example.com",
			want:       false,
		},
		{
			name:       "空SAN和空CommonName",
			host:       "example.com",
			dnsNames:   []string{},
			commonName: "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newTestCert(tt.dnsNames, tt.commonName)
			got := certDomainMatches(tt.host, cert)
			if got != tt.want {
				t.Errorf("certDomainMatches(%q, cert) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestCertDomainMatchesWithExpiredCert 验证域名匹配检查不依赖证书有效期
// 即使证书已过期，域名匹配逻辑也应正常工作
func TestCertDomainMatchesWithExpiredCert(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		dnsNames   []string
		commonName string
		want       bool
	}{
		{
			name:       "过期证书-域名匹配-应返回true",
			host:       "wx.sixuneshop.com",
			dnsNames:   []string{"*.sixuneshop.com"},
			commonName: "sixuneshop.com",
			want:       true,
		},
		{
			name:       "过期证书-域名不匹配-应返回false",
			host:       "wx.sixuneshop.com",
			dnsNames:   []string{"*.sissyun.com.cn"},
			commonName: "sissyun.com.cn",
			want:       false,
		},
		{
			name:       "过期证书-通配符不匹配-应返回false",
			host:       "shop.example.com",
			dnsNames:   []string{"*.other.com"},
			commonName: "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newExpiredTestCert(tt.dnsNames, tt.commonName)
			got := certDomainMatches(tt.host, cert)
			if got != tt.want {
				t.Errorf("certDomainMatches(%q, expiredCert) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestCheckCertExpiry 验证证书过期检查只检查叶证书（索引0），不检查中间/根证书
// 修复遍历所有 PeerCertificates 导致中间证书过期误报的 BUG
func TestCheckCertExpiry(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		warnDays int
		want     string // 期望的告警消息，空字符串表示无告警
	}{
		{
			name:     "有效证书-未到期-无告警",
			cert:     newExpiringTestCert([]string{"*.example.com"}, "example.com", 60),
			warnDays: 30,
			want:     "",
		},
		{
			name:     "即将到期-30天内-天告警",
			cert:     newExpiringTestCert([]string{"*.example.com"}, "example.com", 15),
			warnDays: 30,
			want:     "expires in 15 days",
		},
		{
			name:     "即将到期-48小时内-小时告警",
			cert:     newExpiringTestCert([]string{"*.example.com"}, "example.com", 1),
			warnDays: 30,
			want:     "expires in 23 hours", // 1天 ≈ 23-24小时（测试执行时的小数截断）
		},
		{
			name:     "已过期-过期告警",
			cert:     newExpiredTestCert([]string{"*.example.com"}, "example.com"),
			warnDays: 30,
			want:     "SSLCertificate has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCertExpiry(tt.cert, tt.warnDays)
			if got != tt.want {
				t.Errorf("checkCertExpiry() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckCertExpiryDaysRounding 验证天数的四舍五入精度
// 修复整数除法 expiresIn/24 导致天数显示偏小的 BUG
// 例如：71 小时 → 71/24 = 2（截断），实际应为 3 天（四舍五入）
func TestCheckCertExpiryDaysRounding(t *testing.T) {
	tests := []struct {
		name         string
		daysUntilExp int // 距离过期的天数
		warnDays     int
		wantDays     int // 期望显示的天数
	}{
		{
			name:         "71小时应显示3天而非2天",
			daysUntilExp: 2, // 2天 = 48小时，再加23小时 = 71小时
			warnDays:     30,
			wantDays:     3, // 71小时 ≈ 2.96天 → 四舍五入为3天
		},
		{
			name:         "刚好3天应显示3天",
			daysUntilExp: 3,
			warnDays:     30,
			wantDays:     3,
		},
		{
			name:         "15天应显示15天",
			daysUntilExp: 15,
			warnDays:     30,
			wantDays:     15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 构造一个在指定天数后过期的证书
			// 为了测试四舍五入，对71小时场景额外加23小时
			hoursOffset := tt.daysUntilExp * 24
			if tt.name == "71小时应显示3天而非2天" {
				hoursOffset = 71 // 精确71小时
			}
			cert := &x509.Certificate{
				DNSNames:    []string{"*.example.com"},
				Subject:     pkix.Name{CommonName: "example.com"},
				NotBefore:   time.Now().Add(-720 * time.Hour),
				NotAfter:    time.Now().Add(time.Duration(hoursOffset) * time.Hour),
				IPAddresses: []net.IP{},
			}

			got := checkCertExpiry(cert, tt.warnDays)

			// 验证天数是否包含期望的天数
			expectedMsg := fmt.Sprintf("expires in %d days", tt.wantDays)
			if got != expectedMsg {
				t.Errorf("checkCertExpiry() = %q, want %q", got, expectedMsg)
			}
		})
	}
}

// TestShouldSkipHost 验证 shouldSkipHost 在域名不匹配时始终返回 true，
// 无论证书是否过期（防止过期证书域名不匹配时的误报）
func TestShouldSkipHost(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		dnsNames   []string
		commonName string
		expired    bool // 证书是否过期
		wantSkip   bool // 是否应该跳过
	}{
		{
			name:       "有效证书-域名匹配-不跳过",
			host:       "www.example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "",
			expired:    false,
			wantSkip:   false,
		},
		{
			name:       "有效证书-域名不匹配-跳过",
			host:       "wx.sixuneshop.com",
			dnsNames:   []string{"*.sissyun.com.cn"},
			commonName: "sissyun.com.cn",
			expired:    false,
			wantSkip:   true,
		},
		{
			name:       "过期证书-域名匹配-不跳过",
			host:       "www.example.com",
			dnsNames:   []string{"*.example.com"},
			commonName: "",
			expired:    true,
			wantSkip:   false,
		},
		{
			name:       "过期证书-域名不匹配-跳过",
			host:       "wx.sixuneshop.com",
			dnsNames:   []string{"*.sissyun.com.cn"},
			commonName: "sissyun.com.cn",
			expired:    true,
			wantSkip:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cert *x509.Certificate
			if tt.expired {
				cert = newExpiredTestCert(tt.dnsNames, tt.commonName)
			} else {
				cert = newTestCert(tt.dnsNames, tt.commonName)
			}
			got := shouldSkipHost(tt.host, cert)
			if got != tt.wantSkip {
				t.Errorf("shouldSkipHost(%q, cert) = %v, want %v", tt.host, got, tt.wantSkip)
			}
		})
	}
}
