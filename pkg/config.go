package pkg

import (
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

type ProviderConfig struct {
	Name         string         `yaml:"name"`
	ProviderType string         `yaml:"provider"`
	Addition     map[string]any `yaml:"config"`
	Domains      []string       `yaml:"domains"`
}

func (pc *ProviderConfig) Get(key string) string {
	if pc.Addition[key] == nil {
		log.Fatalln(key, "not exist")
	}
	return pc.Addition[key].(string)
}

type NotifyConfig struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:"config"`
}

func (nc *NotifyConfig) Get(key string) string {
	return nc.Config[key].(string)
}

func NewConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln(err)
	}
	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalln(err)
	}
	return &config
}

type Config struct {
	Timeout   int               `yaml:"timeout"`
	WarnDays  int               `yaml:"warnDays"`
	Providers []*ProviderConfig `yaml:"providers"`
	Notifies  []*NotifyConfig   `yaml:"notifies"`
}
