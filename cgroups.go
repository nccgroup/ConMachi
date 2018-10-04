package main

import (
	"strconv"
	"io/ioutil"
	"fmt"
	"strings"
	"bytes"
)

type deviceRule struct {
	deviceType string
	majorType int
	minorType int
	read bool
	write bool
	mknod bool
}

func (rule *deviceRule) String() string {
	var major, minor string

	if rule.majorType >= 0 {
		major = strconv.Itoa(rule.majorType)
	} else {
		major = "*"
	}

	if rule.minorType >= 0 {
		minor = strconv.Itoa(rule.minorType)
	} else {
		minor = "*"
	}

	types := fmt.Sprintf("%s:%s", major, minor)

	access := ""
	if rule.read {
		access += "r"
	}
	if rule.write {
		access += "w"
	}
	if rule.mknod {
		access += "m"
	}

	return fmt.Sprintf("%s %s %s", rule.deviceType, types, access)
}

type DeviceRules struct {
	rules []*deviceRule
}

func (rules *DeviceRules) String() string {
	s := ""
	for _, rule := range rules.rules {
		s += rule.String() + "\n"
	}
	return s
}

func (rules *DeviceRules) CheckDevice(devType string, majorType int, minorType int, access string) bool {
	for _, rule := range rules.rules {
		if rule.deviceType != "a" && rule.deviceType != devType {
			continue
		}
		if rule.majorType >= 0 && rule.majorType != majorType {
			continue
		}
		if rule.majorType >= 0 && rule.minorType != minorType {
			continue
		}
		if access == "r" && !rule.read {
			continue
		}
		if access == "w" && !rule.write {
			continue
		}
		if access == "m" && !rule.mknod {
			continue
		}
		return true
	}
	return false
}

func (rules *DeviceRules) addRule(entry string) {
	fields := strings.Fields(string(entry))
	if len(fields) == 0 {
		return
	}
	typeParts := strings.Split(fields[1], ":")
	var major, minor int
	if typeParts[0] == "*" {
		major = -1
	} else {
		var err error
		major, err = strconv.Atoi(typeParts[0])
		if err != nil {
			major = -2
		}
	}

	if typeParts[1] == "*" {
		minor = -1
	} else {
		var err error
		minor, err = strconv.Atoi(typeParts[1])
		if err != nil {
			minor = -2
		}
	}

	rule := &deviceRule{
		deviceType: fields[0],
		majorType: major,
		minorType: minor,
		read: strings.Contains(fields[2], "r"),
		write: strings.Contains(fields[2], "w"),
		mknod: strings.Contains(fields[2], "m"),
	}
	rules.rules = append(rules.rules, rule)
}

func NewDeviceRules() (*DeviceRules) {
	return &DeviceRules{
		rules: make([]*deviceRule, 0),
	}
}

func ReadDevices(cgroupDevicesPath string) (*DeviceRules, error) {
	ret := NewDeviceRules()
	data, err := ioutil.ReadFile(cgroupDevicesPath + "/devices.list")
	if err != nil {
		return nil, fmt.Errorf("error reading devices.list: %s", err)
	}
    lines := bytes.Split(data, []byte("\n"))
    for _, line := range lines {
		ret.addRule(string(line))
	}
	return ret, nil
}

func getDangerousDevices(rules *DeviceRules) []*deviceRule {
	/*
    we're just going to assume anything in the docker default is safe and everything
    else is scary and should be disallowed. Maybe we'll loosen this up later
    c 1:5 rwm
    c 1:3 rwm
    c 1:9 rwm
    c 1:8 rwm
    c 5:0 rwm
    c 5:1 rwm
    c *:* m
    b *:* m
    c 1:7 rwm
    c 136:* rwm
    c 5:2 rwm
    c 10:200 rwm
    */
	ret := make([]*deviceRule, 0)
	for _, rule := range rules.rules {
		if rule.deviceType == "a" {
			ret = append(ret, rule)
			continue
		} else if rule.deviceType == "c" {
			if rule.majorType == 1 {
				if rule.minorType == 3 ||  // /dev/null
					rule.minorType == 5 || // /dev/zero
					rule.minorType == 7 || // /dev/full
					rule.minorType == 8 || // /dev/random
					rule.minorType == 9 {  // /dev/urandom
					continue
				}
			} else if rule.majorType == 5 {
				if rule.minorType == 0  ||  // /dev/tty
					rule.minorType == 1 ||  // /dev/console
					rule.minorType == 2 {   // /dev/ptmx
					continue
				}
			} else if rule.majorType == 10 && rule.minorType == 200 {
				continue
			} else if rule.majorType == 136 {
				continue
			}
		}
		if rule.mknod && !rule.read && !rule.write {
			continue
		}
		ret = append(ret, rule)
	}

	return ret
}

func ScanCgroups(state *scanState) ([]*ScanResult, error) {
    // Scan for capability related issues, store capabilities in state
    results := make([]*ScanResult, 0)

	if state.CgroupDeviceRules == nil {
		return results, nil
	}

	// Scan for devices
	allowedDevices := state.CgroupDeviceRules
	dangerousDevices := getDangerousDevices(allowedDevices)
	if len(dangerousDevices) > 0 {
		devlist := ""
		for _, device := range dangerousDevices {
			devlist += device.String() + "\n"
		}
		desc := "The following cgroup device rules allow contianer users to access potentially dangerous devices:\n" + devlist
		result := NewResult("Cgroup allows access to potentially dangerous devices", desc, SEV_MEDIUM)
		results = append(results, result)
	}

	err := ioutil.WriteFile(state.CgroupPath+"/devices/devices.allow",
		[]byte("a"), 0644)
	if err == nil {
		result := NewResult("Cgroups Device Settings Modifiable", "Processes in the conainer can modify the devices cgroup settings which would allow them to access potentially dangerous devices", SEV_HIGH)
		results = append(results, result)
	}

	if state.CgroupCPUShares == 1024 {
		result := NewResult("Cgroup Policy Does Not Restrict CPU Usage", "Processes in the conainer are capable of using excessive amounts of CPU time", SEV_INFO)
		results = append(results, result)
	}

	if state.CgroupMaxMemory > 1024*1024*1024*8 {
		result := NewResult("Cgroup Policy Allows for Excessive Memory Usage", "Processes in the conainer are capable of using excessive amounts (>8GB) of RAM", SEV_INFO)
		results = append(results, result)
	}

    return results, nil
}
