// Copyright 2014 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/utils"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
)

const defaultBrName = "cni0"

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if n.LogToFile != "" {
		f, err := os.OpenFile(n.LogToFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err == nil && f != nil {
			logrus.SetLevel(logrus.DebugLevel)
			logrus.SetOutput(f)
			defer f.Close()
		}
	}

	if n.IsDefaultGW {
		n.IsGW = true
	}

	nArgs, err := loadNetArgs(args.Args)
	if err != nil {
		return err
	}

	br, err := setupBridge(n)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Check if the container interface already exists
	if !checkIfContainerInterfaceExists(args) {
		if err = setupVeth(netns, br, args.IfName, n.MTU, n.HairpinMode); err != nil {
			return err
		}
	} else {
		logrus.Infof("container already has interface: %v, no worries", args.IfName)
	}

	// run the IPAM plugin and get back the config to apply
	result, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// TODO: make this optional when IPv6 is supported
	if result.IP4 == nil {
		return errors.New("IPAM plugin returned missing IPv4 config")
	}

	if result.IP4.Gateway == nil && n.IsGW {
		result.IP4.Gateway = calcGatewayIP(&result.IP4.IP)
	}

	if err := netns.Do(func(_ ns.NetNS) error {
		if nArgs.MACAddress != "" {
			err := setInterfaceMacAddress(args.IfName, string(nArgs.MACAddress))
			if err != nil {
				logrus.Errorf("error setting MAC address: %v", err)
				return fmt.Errorf("couldn't set the MAC Address of the interface: %v", err)
			}
			logrus.Debugf("have set the %v interface %v MAC address: %v", args.ContainerID, args.IfName, nArgs.MACAddress)
		} else {
			logrus.Warnf("no MAC address specified to set for container: %v", args.ContainerID)
		}

		overHeadToUse := 0
		if nArgs.LinkMTUOverhead != "" {
			overHeadToUse, err = strconv.Atoi(string(nArgs.LinkMTUOverhead))
			if err != nil {
				logrus.Errorf("Error converting LinkMTUOverhead: %v to int", nArgs.LinkMTUOverhead)
				overHeadToUse = n.LinkMTUOverhead
			}
		} else {
			overHeadToUse = n.LinkMTUOverhead
		}

		linkMTU := n.MTU - overHeadToUse
		logrus.Debugf("overHeadToUse: %v, linkMTU: %v", overHeadToUse, linkMTU)

		if linkMTU > 0 {
			logrus.Debugf("setting %v linkMTU: %v", args.IfName, linkMTU)
			cIntf, err := netlink.LinkByName(args.IfName)
			if err != nil {
				err = fmt.Errorf("failed to lookup %q: %v", args.IfName, err)
				return err
			}

			err = netlink.LinkSetMTU(cIntf, linkMTU)
			if err != nil {
				err = fmt.Errorf("failed to set link MTU: %v", err)
				return err
			}
		}

		// set the default gateway if requested
		if n.IsDefaultGW {
			_, defaultNet, err := net.ParseCIDR("0.0.0.0/0")
			if err != nil {
				return err
			}

			for _, route := range result.IP4.Routes {
				if defaultNet.String() == route.Dst.String() {
					if route.GW != nil && !route.GW.Equal(result.IP4.Gateway) {
						return fmt.Errorf(
							"isDefaultGateway ineffective because IPAM sets default route via %q",
							route.GW,
						)
					}
				}
			}

			result.IP4.Routes = append(
				result.IP4.Routes,
				types.Route{Dst: *defaultNet, GW: result.IP4.Gateway},
			)

			// TODO: IPV6
		}

		return configureInterface(args.IfName, result)
	}); err != nil {
		return err
	}

	if n.IsGW {
		gwn := &net.IPNet{
			IP:   result.IP4.Gateway,
			Mask: result.IP4.IP.Mask,
		}

		if err = ensureBridgeAddr(br, gwn); err != nil {
			return err
		}

		if err := ip.EnableIP4Forward(); err != nil {
			return fmt.Errorf("failed to enable forwarding: %v", err)
		}
	}

	if n.IPMasq {
		chain := utils.FormatChainName(n.Name, args.ContainerID)
		comment := utils.FormatComment(n.Name, args.ContainerID)
		if err = ip.SetupIPMasq(ip.Network(&result.IP4.IP), chain, comment); err != nil {
			return err
		}
	}

	result.DNS = n.DNS
	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	if n.LogToFile != "" {
		f, err := os.OpenFile(n.LogToFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err == nil && f != nil {
			logrus.SetLevel(logrus.DebugLevel)
			logrus.SetOutput(f)
			defer f.Close()
		}
	}

	if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	var ipn *net.IPNet
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		ipn, err = ip.DelLinkByNameAddr(args.IfName, netlink.FAMILY_V4)
		return err
	})
	if err != nil {
		return err
	}

	if n.IPMasq {
		chain := utils.FormatChainName(n.Name, args.ContainerID)
		comment := utils.FormatComment(n.Name, args.ContainerID)
		if err = ip.TeardownIPMasq(ipn, chain, comment); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.1.0"))
}
