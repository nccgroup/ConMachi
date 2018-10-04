package main

import (
    "fmt"
    "strings"
    "strconv"
)

type Capability uint64
const (
    CAP_CHOWN Capability = 0
    CAP_DAC_OVERRIDE Capability = 1
    CAP_DAC_READ_SEARCH Capability = 2
    CAP_FOWNER Capability = 3
    CAP_FSETID Capability = 4
    CAP_KILL Capability = 5
    CAP_SETGID Capability = 6
    CAP_SETUID Capability = 7
    CAP_SETPCAP Capability = 8
    CAP_LINUX_IMMUTABLE Capability = 9
    CAP_NET_BIND_SERVICE Capability = 10
    CAP_NET_BROADCAST Capability = 11
    CAP_NET_ADMIN Capability = 12
    CAP_NET_RAW Capability = 13
    CAP_IPC_LOCK Capability = 14
    CAP_IPC_OWNER Capability = 15
    CAP_SYS_MODULE Capability = 16
    CAP_SYS_RAWIO Capability = 17
    CAP_SYS_CHROOT Capability = 18
    CAP_SYS_PTRACE Capability = 19
    CAP_SYS_PACCT Capability = 20
    CAP_SYS_ADMIN Capability = 21
    CAP_SYS_BOOT Capability = 22
    CAP_SYS_NICE Capability = 23
    CAP_SYS_RESOURCE Capability = 24
    CAP_SYS_TIME Capability = 25
    CAP_SYS_TTY_CONFIG Capability = 26
    CAP_MKNOD Capability = 27
    CAP_LEASE Capability = 28
    CAP_AUDIT_WRITE Capability = 29
    CAP_AUDIT_CONTROL Capability = 30
    CAP_SETFCAP Capability = 31
    CAP_MAC_OVERRIDE Capability = 32
    CAP_MAC_ADMIN Capability = 33
    CAP_SYSLOG Capability = 34
    CAP_WAKE_ALARM Capability = 35
    CAP_BLOCK_SUSPEND Capability = 36
    CAP_AUDIT_READ Capability = 37
    CAP_MAX Capability = 38
)

func (capv Capability) String() string {
    switch capv {
    case CAP_CHOWN:
        return "CAP_CHOWN"
    case CAP_DAC_OVERRIDE:
        return "CAP_DAC_OVERRIDE"
    case CAP_DAC_READ_SEARCH:
        return "CAP_DAC_READ_SEARCH"
    case CAP_FOWNER:
        return "CAP_FOWNER"
    case CAP_FSETID:
        return "CAP_FSETID"
    case CAP_KILL:
        return "CAP_KILL"
    case CAP_SETGID:
        return "CAP_SETGID"
    case CAP_SETUID:
        return "CAP_SETUID"
    case CAP_SETPCAP:
        return "CAP_SETPCAP"
    case CAP_LINUX_IMMUTABLE:
        return "CAP_LINUX_IMMUTABLE"
    case CAP_NET_BIND_SERVICE:
        return "CAP_NET_BIND_SERVICE"
    case CAP_NET_BROADCAST:
        return "CAP_NET_BROADCAST"
    case CAP_NET_ADMIN:
        return "CAP_NET_ADMIN"
    case CAP_NET_RAW:
        return "CAP_NET_RAW"
    case CAP_IPC_LOCK:
        return "CAP_IPC_LOCK"
    case CAP_IPC_OWNER:
        return "CAP_IPC_OWNER"
    case CAP_SYS_MODULE:
        return "CAP_SYS_MODULE"
    case CAP_SYS_RAWIO:
        return "CAP_SYS_RAWIO"
    case CAP_SYS_CHROOT:
        return "CAP_SYS_CHROOT"
    case CAP_SYS_PTRACE:
        return "CAP_SYS_PTRACE"
    case CAP_SYS_PACCT:
        return "CAP_SYS_PACCT"
    case CAP_SYS_ADMIN:
        return "CAP_SYS_ADMIN"
    case CAP_SYS_BOOT:
        return "CAP_SYS_BOOT"
    case CAP_SYS_NICE:
        return "CAP_SYS_NICE"
    case CAP_SYS_RESOURCE:
        return "CAP_SYS_RESOURCE"
    case CAP_SYS_TIME:
        return "CAP_SYS_TIME"
    case CAP_SYS_TTY_CONFIG:
        return "CAP_SYS_TTY_CONFIG"
    case CAP_MKNOD:
        return "CAP_MKNOD"
    case CAP_LEASE:
        return "CAP_LEASE"
    case CAP_AUDIT_WRITE:
        return "CAP_AUDIT_WRITE"
    case CAP_AUDIT_CONTROL:
        return "CAP_AUDIT_CONTROL"
    case CAP_SETFCAP:
        return "CAP_SETFCAP"
    case CAP_MAC_OVERRIDE:
        return "CAP_MAC_OVERRIDE"
    case CAP_MAC_ADMIN:
        return "CAP_MAC_ADMIN"
    case CAP_SYSLOG:
        return "CAP_SYSLOG"
    case CAP_WAKE_ALARM:
        return "CAP_WAKE_ALARM"
    case CAP_BLOCK_SUSPEND:
        return "CAP_BLOCK_SUSPEND"
    case CAP_AUDIT_READ:
        return "CAP_AUDIT_READ"
    case CAP_MAX:
        return "CAP_MAX"
    default:
        return "UNKNOWN_CAPABILITY"
    }
}

// Capability helpers
func capToIndex(capability Capability) uint64 {
    return uint64(capability >> 5)
}

func capToMask(capability Capability) uint64 {
    return uint64(1 << (capability & 31))
}

type CapData struct {
    CapInh uint64
    CapPrm uint64
    CapEff uint64
    CapBnd uint64
    CapAmb uint64
}

func (cdat *CapData) String() string {
    return fmt.Sprintf("CapInh=%x\nCapPrm=%x\nCapEff=%x\nCapBnd=%x\nCapAmb=%x\n",
                       cdat.CapInh, cdat.CapPrm, cdat.CapEff, cdat.CapBnd, cdat.CapAmb)
}

func CheckCap(mask uint64, capability Capability) bool {
    if (capToMask(capability) & mask) > 0 {
        return true
    }
    return false
}

func GetCaps(mask uint64) []Capability {
    result := make([]Capability, 0)
    var i uint64
    for i=0; i<uint64(CAP_MAX); i++ {
        if CheckCap(mask, Capability(i)) {
            result = append(result, Capability(i))
        }
    }
    return result
}

func isDefaultDockerCap(capv Capability) bool {
    switch capv {
        case CAP_CHOWN,
             CAP_DAC_OVERRIDE,
             CAP_FOWNER,
             CAP_FSETID,
             CAP_KILL,
             CAP_SETGID,
             CAP_SETUID,
             CAP_SETPCAP,
             CAP_NET_BIND_SERVICE,
             CAP_NET_RAW,
             CAP_SYS_CHROOT,
             CAP_MKNOD,
             CAP_AUDIT_WRITE,
             CAP_SETFCAP,
             CAP_MAC_OVERRIDE,
             CAP_MAC_ADMIN,
             CAP_WAKE_ALARM,
             CAP_BLOCK_SUSPEND,
             CAP_AUDIT_READ:
            return true
    }
    return false
}

func listCaps(caps []Capability) string {
	capstrs := make([]string, 0)
	for _, capv := range caps {
		capstrs = append(capstrs, capv.String())
	}
	return strings.Join(capstrs, ", ")
}

func loadCaps(state *scanState) {
	// Load capability data into scanState
	caps, err := ReadCaps(state)
    if err != nil {
        return
    }
    state.Capabilities = caps
}

func capLine(caps uint64) string {
	// returns summary of capabilities with hex and list form
	return fmt.Sprintf("(%016x): %s", caps, listCaps(GetCaps(caps)))
}

func ScanCaps(state *scanState) ([]*ScanResult, error) {
    // Scan for capability related issues, store capabilities in state
    results := make([]*ScanResult, 0)
	InfoLog.Println("Scanning for capability issues")

	// Create info finding with all caps
	desc := ""
	desc += fmt.Sprintf("CapInh %s\n", capLine(state.Capabilities.CapInh))
	desc += fmt.Sprintf("CapPrm %s\n", capLine(state.Capabilities.CapPrm))
	desc += fmt.Sprintf("CapEff %s\n", capLine(state.Capabilities.CapEff))
	desc += fmt.Sprintf("CapBnd %s\n", capLine(state.Capabilities.CapBnd))
	desc += fmt.Sprintf("CapAmb %s\n", capLine(state.Capabilities.CapAmb))
	res := NewResult("Container Capabilities", desc, SEV_INFO)
	results = append(results, res)

    // Check for non-default capabilities
    defResults, err := ScanDefaultCaps(state)
    if err != nil {
        InfoLog.Printf("error checking default capabilities: %s", err)
    } else {
		results = append(results, defResults...)
	}

    // Flag any extra saucy capabilities
    dangResults, err := ScanDangerousCaps(state)
    if err != nil {
        InfoLog.Printf("error checking default capabilities: %s", err)
    } else {
		results = append(results, dangResults...)
	}

    return results, nil
}

func ScanDefaultCaps(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)

	// Only check default caps for docker containers
	if state.Runtime != RuntimeDocker {
		return results, nil
	}

    badCaps := make([]Capability, 0)
    for _, capv := range GetCaps(state.Capabilities.CapBnd) {
        if !isDefaultDockerCap(capv) {
            badCaps = append(badCaps, capv)
        }
    }
    if len(badCaps) > 0 {
		caplist := listCaps(badCaps)
        InfoLog.Printf("Found non-default Docker capabilities in CapBnd: %s", caplist)
        desc := fmt.Sprintf("Container has non-default Docker capabilities in CapBnd: %s", caplist)
        res := NewResult("Container has non-default Docker capabilities in CapBnd", desc, SEV_MEDIUM)
        results = append(results, res)
    }
    return results, nil
}

func isDangerousCap(cap Capability) bool {
	switch cap {
	case CAP_DAC_READ_SEARCH,
		CAP_SYS_ADMIN,
		CAP_SYS_RAWIO,
		CAP_SYS_MODULE,
		CAP_SYS_PTRACE:
		return true
	default:
		return false
	}
}

func isNetworkAttackCap(cap Capability) bool {
	switch cap {
		case CAP_NET_ADMIN,
		     CAP_NET_RAW:
		  return true;
	}
	return false
}

func ScanDangerousCaps(state *scanState) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)

    dangerousBnd := make([]Capability, 0)
    networkBnd := make([]Capability, 0)
    for _, capv := range GetCaps(state.Capabilities.CapBnd) {
        if isDangerousCap(capv) {
            dangerousBnd = append(dangerousBnd, capv)
        }
        if isNetworkAttackCap(capv) {
            networkBnd = append(networkBnd, capv)
        }
    }

    dangerousEff := make([]Capability, 0)
    networkEff := make([]Capability, 0)
    for _, capv := range GetCaps(state.Capabilities.CapEff) {
        if isDangerousCap(capv) {
            dangerousEff = append(dangerousEff, capv)
        }
        if isNetworkAttackCap(capv) {
            networkEff = append(networkEff, capv)
        }
    }

	desc := ""
	title := "Container has potentially dangerous capabilities"
	sev := SEV_INFO

    if len(networkBnd) > 0 {
		caplist := listCaps(networkBnd)
        desc += fmt.Sprintf("* Container has capabilities in the CapBnd set which could enable network attacks if a process runs with uid=0: %s\n", caplist)
		sev = SEV_MEDIUM
    }

    if len(networkEff) > 0 {
		caplist := listCaps(networkEff)
        desc += fmt.Sprintf("* Container has capabilities in the CapEff which could enable network attacks at the current privilege level: %s\n", caplist)
		sev = SEV_MEDIUM
    }

    if len(dangerousBnd) > 0 {
		caplist := listCaps(dangerousBnd)
        desc += fmt.Sprintf("* Container has dangerous capabilities in the CapBnd set which may allow for container escape if a process runs with uid=0: %s\n", caplist)
		sev = SEV_MEDIUM
    }

    if len(dangerousEff) > 0 {
		caplist := listCaps(dangerousEff)
		title = "Container has dangerous capabilities"
        desc += fmt.Sprintf("* Container has dangerous capabilities in the CapEff set which may allow for container escape if a process runs at the current privilege level: %s\n", caplist)
		sev = SEV_CRITICAL
    }

	if len(desc) > 0 {
        res := NewResult(title, desc, sev)
		results = append(results, res)
	}
	
    return results, nil
}

func ReadCaps(state *scanState) (*CapData, error) {
    result := &CapData{
    }
    var parsed uint64
    var v string

    v = state.ProcStatus["CapInh"]
    parsed, err := strconv.ParseUint(v, 16, 64)
    if err != nil {
        return nil, fmt.Errorf("error parsing capability value: %s", v)
    }
    result.CapInh = parsed

    v = state.ProcStatus["CapPrm"]
    parsed, err = strconv.ParseUint(v, 16, 64)
    if err != nil {
        return nil, fmt.Errorf("error parsing capability value: %s", v)
    }
    result.CapPrm = parsed

    v = state.ProcStatus["CapEff"]
    parsed, err = strconv.ParseUint(v, 16, 64)
    if err != nil {
        return nil, fmt.Errorf("error parsing capability value: %s", v)
    }
    result.CapEff = parsed

    v = state.ProcStatus["CapBnd"]
    parsed, err = strconv.ParseUint(v, 16, 64)
    if err != nil {
        return nil, fmt.Errorf("error parsing capability value: %s", v)
    }
    result.CapBnd = parsed

    v = state.ProcStatus["CapAmb"]
    parsed, err = strconv.ParseUint(v, 16, 64)
    if err != nil {
        return nil, fmt.Errorf("error parsing capability value: %s", v)
    }
    result.CapAmb = parsed

    return result, nil
}
