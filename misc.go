package main

import (
	"fmt"
    "io/ioutil"
	"os"
)

func RWFile(path string) (bool) {
	// Attempts to read a file and write its contents back to the file
	// Used to check for read/write permissions
	// Returns whether successful
    data, err := ioutil.ReadFile(path)
    if err == nil {
		err = ioutil.WriteFile(path, data, 0644)
		if err == nil {
			return true
		}
    }
	return false
}

func SeccompMode(state *scanState) (string, error) {
	if val, ok := state.ProcStatus["Seccomp"]; ok {
		if val == "0" {
			return "disabled", nil
		} else if val == "1" {
			return "strict", nil
		} else if val == "2" {
			return "filtered", nil
		}
	}
	return "", fmt.Errorf("error scanning for seccomp profile")
}

func ScanMisc(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	var result []*ScanResult
	var err error

	// Scan Runtime
    result, err = ScanRuntime(state)
    if err != nil {
        InfoLog.Printf("error scanning runtime: %s", err)
    } else {
		results = append(results, result...)
	}

	// Check for user namespacing
    result, err = ScanUserNamespacing(state)
    if err != nil {
        InfoLog.Printf("error checking for user namespacing: %s", err)
    } else {
		results = append(results, result...)
	}

    // Check for proc namespacing
    result, err = ScanProcessNamespacing(state)
    if err != nil {
        InfoLog.Printf("error checking for process namespacing: %s", err)
    } else {
		results = append(results, result...)
	}

	// Check for core_pattern
    result, err = ScanProcVars(state)
    if err != nil {
        InfoLog.Printf("error checking for namespacing: %s", err)
    } else {
		results = append(results, result...)
	}

	// Check for kcore
    result, err = ScanKcore(state)
    if err != nil {
        InfoLog.Printf("error checking for kcore: %s", err)
    } else {
		results = append(results, result...)
	}

    // Check for AppArmor
    result, err = ScanAppArmor(state)
    if err != nil {
        InfoLog.Printf("error checking for AppArmor profile: %s", err)
    } else {
		results = append(results, result...)
	}

    // Check for seccomp
    result, err = ScanSeccompEnabled(state)
    if err != nil {
        InfoLog.Printf("error checking if seccomp is enabled: %s", err)
    } else {
		results = append(results, result...)
	}

	// Scan CPUInfo
    result, err = ScanProcCPUInfo(state)
    if err != nil {
        InfoLog.Printf("error scanning CPU info: %s", err)
    } else {
		results = append(results, result...)
	}

    // get kernel version
    versionresults, err := ScanVersion(state)
    if err != nil {
        InfoLog.Printf("error finding kernel version: %s", err)
    } else {
		results = append(results, versionresults...)
	}

    return results, nil
}

func ScanVersion(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
    data, err := ioutil.ReadFile("/proc/version")
    if err != nil {
        InfoLog.Printf("could not open /proc/version: %s. Trying /proc/sys/kernel/version", err)
        data, err = ioutil.ReadFile("/proc/sys/kernel/version")
        if err != nil {
            InfoLog.Printf("could not open /proc/sys/kernel/version: %s, giving up on finding version info", err)
			return results, nil
        }
    }
    
    result := NewResult("Kernel Version Info", string(data), SEV_INFO)
    results = append(results, result)
    return results, nil
}

func ScanProcessNamespacing(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	hasNs, err := HasNamespace("pid")
	if err != nil {
		InfoLog.Printf("error checking pid namespacing: %s\n", err)
		return results, nil
	}
    if !hasNs {
        result := NewResult("Container not using process namespaces", "Container is not using process namespaces. This allows contained processes to interact with uncontained processes", SEV_HIGH)
        results = append(results, result)
    }
    return results, nil
}

func ScanSeccompEnabled(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	mode, _ := SeccompMode(state)
    if mode == "disabled" {
        result := NewResult("Seccomp is Disabled", "Seccomp is disabled in container", SEV_LOW)
        results = append(results, result)
    }
    return results, nil
}

func ScanProcVars(state *scanState) ([]*ScanResult, error) {
	// Checks if we can read/write to various /proc files
    results := make([]*ScanResult, 0)

	if RWFile("/proc/sys/kernel/core_pattern") {
		result := NewResult("/proc/sys/kernel/core_pattern is writable", "/proc/sys/kernel/core_pattern is writable which allows for container escape", SEV_CRITICAL)
        results = append(results, result)
	}

	if RWFile("/proc/sys/kernel/modprobe") {
		result := NewResult("/proc/sys/kernel/modprobe is writable", "/proc/sys/kernel/modprobe is writable which allows for container escape", SEV_CRITICAL)
        results = append(results, result)
	}

	if RWFile("/proc/sys/vm/panic_on_oom") {
		result := NewResult("/proc/sys/vm/panic_on_oom is writable", "/proc/sys/vm/panic_on_oom is writable which could allow a contained process to crash the host", SEV_LOW)
        results = append(results, result)
	}
    return results, nil
}

func ScanKcore(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	// Open kcore, kmem, mem RW then confirm we can actually get data out of it
	f, err := os.OpenFile("/proc/kcore", os.O_RDWR, 0644)
	if err == nil {
		b := make([]byte, 3)
		n, err := f.Read(b)
		if err == nil && n > 0 {
			f.Close()
			result := NewResult("/proc/kcore is writable", "/proc/kcore is writable which allows for container escape", SEV_CRITICAL)
			results = append(results, result)
		}
	}

	// kmem
	f, err = os.OpenFile("/proc/kmem", os.O_RDWR, 0644)
	if err == nil {
		b := make([]byte, 3)
		n, err := f.Read(b)
		if err == nil && n > 0 {
			f.Close()
			result := NewResult("/proc/kmem is writable", "/proc/kmem is writable which allows for container escape", SEV_CRITICAL)
			results = append(results, result)
		}
	}

	// mem
	f, err = os.OpenFile("/proc/mem", os.O_RDWR, 0644)
	if err == nil {
		b := make([]byte, 3)
		n, err := f.Read(b)
		if err == nil && n > 0 {
			f.Close()
			result := NewResult("/proc/mem is writable", "/proc/mem is writable which allows for container escape", SEV_CRITICAL)
			results = append(results, result)
		}
	}

    return results, nil
}

func ScanProcCPUInfo(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	bugstr := ""
	isFinding := false
	for _, p := range state.ProcCPUInfo {
		var ok bool
		var bugline string
		if bugline, ok = p["bugs"]; !ok {
			continue
		}

		var proc string
		if proc, ok = p["processor"]; !ok {
			proc = "??"
		}

		isFinding = true
		var mname string
		if mname, ok = p["model name"]; ok {
			bugstr += fmt.Sprintf("Processor %s (%s) bugs: %s\n", proc, mname, bugline)
		} else {
			bugstr += fmt.Sprintf("Processor %s bugs: %s\n", proc, bugline)
		}
	}
	if isFinding {
		desc := "The following processors have bugs which may be exploited. More information about each of the processors can be found by reading /proc/cpuinfo.\n\n" + bugstr
		result := NewResult("Processor Vulnerable to Hardware Attacks", desc, SEV_LOW)
		results = append(results, result)
	}
    return results, nil
}

func ScanRuntime(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	desc := fmt.Sprintf("Container runtime: %s", state.Runtime)
	result := NewResult("Detected Container Runtime", desc, SEV_INFO)
	results = append(results, result)
	return results, nil
}

func ScanAppArmor(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	f := readFile("/proc/self/attr/current")
	if f == "unconfined" || f == "" {
		result := NewResult("Container Running Unconfined AppArmor Profile",
			"Container is not enforcing an AppArmor profile on contained processes",
			SEV_LOW)
		results = append(results, result)
	} else {
		desc := fmt.Sprintf("AppArmor Profile: %s", f)
		result := NewResult("AppArmor Profile", desc, SEV_INFO)
		results = append(results, result)
	}
	return results, nil
}

func ScanUserNamespacing(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	isNamespaced, mappings := UserNamespace()
	if isNamespaced {
		var desc string
		if mappings == nil {
			desc = "User namespacing enabled but not initialized therefore there are no mappings."
		} else {
			desc = "User namespacing enabled. The following mappings were detected:\n"
			for _, mapping := range mappings {
				desc += fmt.Sprintf("\nContainer -> %d / Host -> %d / Range -> %d", mapping.ContainerID, mapping.HostID, mapping.Range)
			}
		}
		result := NewResult("User Namespace Mappings", desc, SEV_INFO)
		results = append(results, result)
	} else {
		result := NewResult("User Namespace Disabled",
			"User namespacing is not enabled. As a result, if a contained process is running with uid=0 it will be running as a privileged user if it gains access to resources outside of the container.",
			SEV_MEDIUM)
		results = append(results, result)
	}
	return results, nil
}
