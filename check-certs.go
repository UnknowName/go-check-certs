package main

import (
	"flag"
	"go-check-certs/pkg"
	"log"
	"time"
)

const (
	cacheSize     = 50
	checkInterval = time.Hour * 24
)

var configFile string

func init() {
	flag.StringVar(&configFile, "config", "config.yaml", "config file")
	flag.Parse()
}

func main() {
	log.Println("DEBUG App start, use config file", configFile)
	config := pkg.NewConfig(configFile)
	hostChan := make(chan string, cacheSize)
	resChan := make(chan pkg.CheckResult)
	waitTime := time.Duration(config.Timeout) * 10 * time.Second
	for _, nc := range config.Notifies {
		notify := pkg.NewNotify(nc, resChan)
		go notify.Send(waitTime)
	}
	for {
		log.Println("DEBUG start new check")
		for _, pConf := range config.Providers {
			provider := pkg.NewProvider(pConf)
			go provider.GetAllRecords(hostChan)
		}
		check := pkg.NewSimpleCheck(hostChan, resChan)
		check.Check(config.WarnDays)
		time.Sleep(checkInterval - waitTime)
	}
}
