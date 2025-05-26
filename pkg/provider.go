package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	alidns20150109 "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultSize = 100
	maxRetry    = 3
	aliyun      = "aliyun"
	file        = "file"
	west        = "west"
	baseURL     = "https://api.west.cn/API/v2/domain/dns/"
	queryAction = "dnsrec.list"
	enable      = "ENABLE"
)

var dnsTypes = [2]string{"A", "CNAME"}

func NewProvider(config *ProviderConfig) Provider {
	switch config.ProviderType {
	case aliyun:
		return newAliyunProvider(
			config.Get("keyId"),
			config.Get("keySecret"),
			config.Get("region"),
			strings.Split(config.Get("domains"), ","))
	case file:
		return newFileProvider(config.Get("filePath"))
	case west:
		return &WestDigitalProvider{
			apiKey:  config.Get("apiKey"),
			domains: strings.Split(config.Get("domains"), ","),
		}
	default:
		log.Fatalln("doesn't support provider", config.ProviderType)
	}
	return nil
}

type Provider interface {
	GetAllRecords(ch chan<- string) // 结果写入ch，后续协程消费
}

func newAliyunProvider(keyId, keySecret, region string, domains []string) *AliyunProvider {
	config := &openapi.Config{
		AccessKeyId:     tea.String(keyId),
		AccessKeySecret: tea.String(keySecret),
	}
	var endpoint string
	if region == "cn-qingdao" || region == "cn-wulanchabu" {
		endpoint = "dns.aliyuncs.com"
	} else {
		endpoint = fmt.Sprintf("alidns.%s.aliyuncs.com", region)
	}
	config.Endpoint = tea.String(endpoint)
	client, err := alidns20150109.NewClient(config)
	if err != nil {
		log.Fatalln(err)
	}
	p := &AliyunProvider{
		client:  client,
		region:  region,
		domains: domains,
	}
	return p
}

type AliyunProvider struct {
	client  *alidns20150109.Client
	region  string
	domains []string
}

func (ap *AliyunProvider) fetchWithRetry(domain, dnsType string, page, pageSize int64, out chan<- string) (int64, error) {
	describeDomainRecordsRequest := &alidns20150109.DescribeDomainRecordsRequest{
		Lang:       tea.String("en"),
		PageSize:   tea.Int64(pageSize),
		PageNumber: tea.Int64(page),
		DomainName: tea.String(domain),
		Type:       tea.String(dnsType),
		Status:     tea.String(enable),
	}
	var lastErr error
	for retry := 0; retry < maxRetry; retry++ {
		runtime := &util.RuntimeOptions{}
		resp, err := ap.client.DescribeDomainRecordsWithOptions(describeDomainRecordsRequest, runtime)
		if err == nil && *resp.StatusCode == http.StatusOK {
			for _, record := range resp.Body.DomainRecords.Record {
				out <- fmt.Sprintf("%s.%s", *record.RR, domain)
			}
			cnt := *resp.Body.TotalCount / defaultSize
			if *resp.Body.TotalCount%defaultSize != 0 {
				cnt++
			}
			return cnt, nil
		} else {
			lastErr = err
		}
	}
	return -1, lastErr
}

func (ap *AliyunProvider) getRecords(domain, dnsType string, out chan<- string) {
	totalPage, err := ap.fetchWithRetry(domain, dnsType, 1, defaultSize, out)
	if err != nil || totalPage < 0 {
		log.Printf("Get domain %s total page failed %s", domain, err)
		return
	}
	// 从第2页开始，因此减少1
	for page := int64(2); page <= totalPage; page++ {
		go ap.fetchWithRetry(domain, dnsType, page, defaultSize, out)
	}
}

func (ap *AliyunProvider) GetAllRecords(out chan<- string) {
	for _, domain := range ap.domains {
		for _, dnsType := range dnsTypes {
			go ap.getRecords(strings.TrimSpace(domain), dnsType, out)
		}
	}
}

// file
func newFileProvider(path string) *FileProvider {
	return &FileProvider{file: path}
}

type FileProvider struct {
	file string
}

func (fp *FileProvider) GetAllRecords(out chan<- string) {
	contents, err := os.ReadFile(fp.file)
	if err != nil {
		log.Println("WARN read file error", err)
		return
	}
	lines := strings.Split(string(contents), "\n")
	for _, line := range lines {
		host := strings.TrimSpace(line)
		if len(host) == 0 || host[0] == '#' {
			continue
		}
		out <- host
	}
}

// WestDigital

type WBody struct {
	Items []map[string]any `json:"items"`
}

type WestResponse struct {
	Code int   `json:"code"`
	Body WBody `json:"body"`
}

type WestDigitalProvider struct {
	apiKey  string
	domains []string
}

func (wd *WestDigitalProvider) GetAllRecords(ch chan<- string) {
	for _, domain := range wd.domains {
		for _, recordType := range dnsTypes {
			go func(domain, recordType string) {
				for i := 0; i < maxRetry; i++ {
					if err := wd.queryDomainRecord(domain, recordType, ch); err != nil {
						log.Println("WARN provider west digital get record failed, try again in 1 seconds")
						time.Sleep(time.Second)
						continue
					}
					return
				}
				log.Println("ERROR provider west digital failed exceed ", maxRetry)
			}(domain, recordType)
		}
	}
}

func (wd *WestDigitalProvider) doAction(path string, param map[string]string, isGet bool) ([]byte, error) {
	var apiPath string
	if path != "" {
		apiPath = fmt.Sprintf("%s%s", baseURL, path)
	} else {
		apiPath = baseURL
	}
	var req *http.Request
	var err error
	query := url.Values{}
	query.Add("apidomainkey", wd.apiKey)
	for k, v := range param {
		query.Add(k, v)
	}
	client := &http.Client{Timeout: defaultTimeout}
	if isGet {
		req, err = http.NewRequest(http.MethodGet, apiPath, nil)
		if err != nil {
			return nil, err
		}
	} else {
		req, err = http.NewRequest(http.MethodPost, apiPath, strings.NewReader(query.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=GBK")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (wd *WestDigitalProvider) queryDomainRecord(domain, recordType string, out chan<- string) error {
	param := map[string]string{
		"act":         queryAction,
		"domain":      domain,
		"record_type": recordType,
	}
	resp, err := wd.doAction("", param, false)
	if err != nil {
		return err
	}
	wp := new(WestResponse)
	if err = json.Unmarshal(resp, wp); err != nil {
		return err
	}
	if wp.Code == 500 {
		return errors.New("remote provider service error")
	}
	for _, record := range wp.Body.Items {
		if record["pause"].(float64) == 0 {
			out <- fmt.Sprintf("%s.%s", record["hostname"], domain)
		}
	}
	return nil
}
