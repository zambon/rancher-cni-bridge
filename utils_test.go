package main

import (
	"os"
	"testing"

	"github.com/Sirupsen/logrus"
)

// Some of the tests can run only when in development,
// remember to disable this before commiting the code.
const inDevelopment = false

func TestFindMACAddressForContainer(t *testing.T) {
	if !inDevelopment {
		t.Skip("not in development mode")
	}

	cid := os.Getenv("TEST_CONTAINER_ID")
	if cid == "" {
		logrus.Errorf("Please set environment variable TEST_CONTAINER_ID to continue")
		t.Fail()
		return
	}

	m, err := findMACAddressForContainer("", "")
	if err != nil {
		logrus.Errorf("couldn't find mac address")
		t.Fail()
	}
	logrus.Infof("Got MAC address: %v", m)
}
