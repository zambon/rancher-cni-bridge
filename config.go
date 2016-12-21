package main

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
)

// NetConf is used to hold the config of the network
type NetConf struct {
	types.NetConf
	BrName          string `json:"bridge"`
	BrSubnet        string `json:"bridgeSubnet"`
	BrIP            string `json:"bridgeIP"`
	LogToFile       string `json:"logToFile"`
	IsGW            bool   `json:"isGateway"`
	IsDefaultGW     bool   `json:"isDefaultGateway"`
	IPMasq          bool   `json:"ipMasq"`
	MTU             int    `json:"mtu"`
	LinkMTUOverhead int    `json:"linkMTUOverhead"`
	HairpinMode     bool   `json:"hairpinMode"`
}

func loadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{
		BrName: defaultBrName,
	}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}
