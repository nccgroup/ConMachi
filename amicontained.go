/*
The MIT License (MIT)

Copyright (c) 2018 The Genuinetools Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"fmt"
	"syscall"
	"strconv"
	"io/ioutil"
	"strings"
	"os"
)

const (
	// RuntimeDocker is the string for the docker runtime.
	RuntimeDocker = "docker"
	// RuntimeSingularity is the string for the Singularity runtime
	RuntimeSingularity = "singularity"
	// RuntimeRkt is the string for the rkt runtime.
	RuntimeRkt = "rkt"
	// RuntimeNspawn is the string for the systemd-nspawn runtime.
	RuntimeNspawn = "systemd-nspawn"
	// RuntimeLXC is the string for the lxc runtime.
	RuntimeLXC = "lxc"
	// RuntimeLXCLibvirt is the string for the lxc-libvirt runtime.
	RuntimeLXCLibvirt = "lxc-libvirt"
	// RuntimeOpenVZ is the string for the openvz runtime.
	RuntimeOpenVZ = "openvz"
	// RuntimeKubernetes is the string for the kubernetes runtime.
	RuntimeKubernetes = "kube"
	// RuntimeGarden is the string for the garden runtime.
	RuntimeGarden = "garden"
	// RuntimePodman is the string for the podman runtime.
	RuntimePodman = "podman"

	uint32Max = 4294967295
)


func readFile(file string) string {
	if !fileExists(file) {
		return ""
	}

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		return true
	}
	return false
}

func deleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if strings.TrimSpace(str) != "" {
			r = append(r, strings.TrimSpace(str))
		}
	}
	return r
}

// Taken from https://github.com/genuinetools/amicontained/blob/c0168981b856dd8a81b02ed6ed81a8d67e37cfd2/container/container.go#L48
// DetectRuntime returns the container runtime the process is running in.
func DetectRuntime() (string, error) {
	runtimes := []string{RuntimeDocker, RuntimeSingularity, RuntimeRkt, RuntimeNspawn, RuntimeLXC, RuntimeLXCLibvirt, RuntimeOpenVZ, RuntimeKubernetes, RuntimeGarden, RuntimePodman}

	// read the cgroups file
	cgroups := readFile("/proc/self/cgroup")
	if len(cgroups) > 0 {
		for _, runtime := range runtimes {
			if strings.Contains(cgroups, runtime) {
				return runtime, nil
			}
		}
	}

	if fileExists("/.singularity.d") && fileExists("/singularity") {
		return RuntimeSingularity, nil
	}

	// /proc/vz exists in container and outside of the container, /proc/bc only outside of the container.
	if fileExists("/proc/vz") && !fileExists("/proc/bc") {
		return RuntimeOpenVZ, nil
	}

	ctrenv := os.Getenv("container")
	if ctrenv != "" {
		for _, runtime := range runtimes {
			if ctrenv == runtime {
				return runtime, nil
			}
		}
	}

	// PID 1 might have dropped this information into a file in /run.
	// Read from /run/systemd/container since it is better than accessing /proc/1/environ,
	// which needs CAP_SYS_PTRACE
	f := readFile("/run/systemd/container")
	if len(f) > 0 {
		for _, runtime := range runtimes {
			if f == runtime {
				return runtime, nil
			}
		}
	}

	return "not-found", nil
}

// HasNamespace determines if the container is using a particular namespace or the
// host namespace.
// The device number of an unnamespaced /proc/1/ns/{ns} is 4 and anything else is
// higher.
func HasNamespace(ns string) (bool, error) {
	file := fmt.Sprintf("/proc/1/ns/%s", ns)

	// Use Lstat to not follow the symlink.
	var info syscall.Stat_t
	if err := syscall.Lstat(file, &info); err != nil {
		return false, &os.PathError{Op: "lstat", Path: file, Err: err}
	}

	// Get the device number. If it is higher than 4 it is in a namespace.
	if info.Dev > 4 {
		return true, nil
	}

	return false, nil
}


// UserMapping holds the values for a {uid,gid}_map.
type UserMapping struct {
	ContainerID int64
	HostID      int64
	Range       int64
}

// UserNamespace determines if the container is running in a UserNamespace and returns the mappings if so.
func UserNamespace() (bool, []UserMapping) {
	f := readFile("/proc/self/uid_map")
	if len(f) < 0 {
		// user namespace is uninitialized
		return true, nil
	}

	userNs, mappings, err := readUserMappings(f)
	if err != nil {
		return false, nil
	}

	return userNs, mappings
}

func readUserMappings(f string) (iuserNS bool, mappings []UserMapping, err error) {
	parts := strings.Split(f, " ")
	parts = deleteEmpty(parts)
	if len(parts) < 3 {
		return false, nil, nil
	}

	for i := 0; i < len(parts); i += 3 {
		nsu, hu, r := parts[i], parts[i+1], parts[i+2]
		mapping := UserMapping{}

		mapping.ContainerID, err = strconv.ParseInt(nsu, 10, 0)
		if err != nil {
			return false, nil, nil
		}
		mapping.HostID, err = strconv.ParseInt(hu, 10, 0)
		if err != nil {
			return false, nil, nil
		}
		mapping.Range, err = strconv.ParseInt(r, 10, 0)
		if err != nil {
			return false, nil, nil
		}

		if mapping.ContainerID == 0 && mapping.HostID == 0 && mapping.Range == uint32Max {
			return false, nil, nil
		}

		mappings = append(mappings, mapping)
	}

	return true, mappings, nil
}
