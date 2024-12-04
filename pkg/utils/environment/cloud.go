package environment

import (
	"os"
	"strings"
)

type CloudProvider uint32

const (
	Unknown CloudProvider = iota
	AWS
	Azure
	GCP
	Alibaba
	Oracle
	DigitalOcean
	Vultr
)

func (c CloudProvider) String() string {
	if str, ok := cloudProviderNames[c]; ok {
		return str
	}

	return cloudProviderNames[Unknown]
}

var cloudProviderNames = map[CloudProvider]string{
	Unknown:      "Unknown/None",
	AWS:          "AWS",
	Azure:        "Azure",
	GCP:          "GCP",
	Alibaba:      "Alibaba",
	Oracle:       "Oracle",
	DigitalOcean: "Digital Ocean",
	Vultr:        "Vultr",
}

var cloudProviderDetectFuncs = map[CloudProvider]func() bool{
	AWS:          DetectAWS,
	Azure:        DetectAzure,
	GCP:          DetectGCP,
	Alibaba:      DetectAlibaba,
	Oracle:       DetectOracle,
	DigitalOcean: DetectDigitalOcean,
	Vultr:        DetectVultr,
}

func DetectCloudProvider() CloudProvider {
	for provider, detecFunc := range cloudProviderDetectFuncs {
		if detecFunc() {
			return provider
		}
	}

	return Unknown
}

func DetectAWS() bool {
	for _, vendorFile := range []string{
		"/sys/class/dmi/id/product_version",
		"/sys/class/dmi/id/bios_vendor",
	} {
		data, err := os.ReadFile(vendorFile)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(data)), "amazon") {
			return true
		}
	}
	return false
}

func DetectAzure() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Microsoft Corporation")
}

func DetectGCP() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Google")
}

func DetectAlibaba() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Alibaba Cloud ECS")
}

func DetectOracle() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "OracleCloud")
}

func DetectDigitalOcean() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "DigitalOcean")
}

func DetectVultr() bool {
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "Vultr")
}
