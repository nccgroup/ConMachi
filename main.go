package main

import(
    "fmt"
	"flag"
    "os"
    "bytes"
	"strconv"
    "io/ioutil"
	"strings"
	"log"
)

var InfoLog *log.Logger

type SeverityLevel int
const (
    SEV_INFO SeverityLevel = iota
    SEV_LOW
    SEV_MEDIUM
    SEV_HIGH
    SEV_CRITICAL
)
func (sev SeverityLevel) String() string {
    switch sev {
    case SEV_INFO:
        return "Informational"
    case SEV_LOW:
        return "Low"
    case SEV_MEDIUM:
        return "Medium"
    case SEV_HIGH:
        return "High"
    case SEV_CRITICAL:
        return "Critical"
    default:
        return "Unknown"
    }
}

type CmdOptions struct {
	LogFile     string
	IPSniffTime int
	MinimumSeverity SeverityLevel
	KubernetesScan bool
}

type scanState struct {
    Capabilities      *CapData
    ProcStatus        map[string]string
	ProcCPUInfo       []map[string]string
	CmdOpts           *CmdOptions
	Runtime           string
	CgroupDeviceRules *DeviceRules
	CgroupPath        string
	CgroupCPUShares   uint64
	CgroupMaxMemory   uint64
}

func NewScanState() *scanState {
    return &scanState{
        ProcStatus: make(map[string]string),
        ProcCPUInfo: make([]map[string]string, 0),
    }
}

func ParseArgs() (*CmdOptions, error) {
	opts := &CmdOptions{}
	//var MinSevStr string

	flag.StringVar(&opts.LogFile, "l", "", "File to log to")
	flag.IntVar(&opts.IPSniffTime, "sniff", 0, "Sniff the network for IP addresses for a given number of seconds")
	//flag.StringVar(&MinSevStr, "s", "info", "Minimum severity to include in output")
	//flag.BoolVar(&opts.KubernetesScan, "k", false, "Check for Kubernetes related issues")
	flag.Parse()

	/*
	switch strings.ToLower(MinSevStr)[0] {
	case 'i':
		opts.MinimumSeverity = SEV_INFO
	case 'l':
		opts.MinimumSeverity = SEV_LOW
	case 'm':
		opts.MinimumSeverity = SEV_MEDIUM
	case 'h':
		opts.MinimumSeverity = SEV_HIGH
	case 'c':
		opts.MinimumSeverity = SEV_CRITICAL
	default:
		return nil, fmt.Errorf("Unknown severity level: %s", MinSevStr)
	}
    */
	opts.MinimumSeverity = SEV_INFO // we're just using severity for sorting for now
	opts.KubernetesScan = false // we'll add the flag back once it's implemented

	return opts, nil
}

func (state *scanState) ReadData() error {
    data, err := ioutil.ReadFile("/proc/self/status")
    if err != nil {
        InfoLog.Printf("could not open /proc/1/status: %s", err)
    } else {
		strs := bytes.Split(data, []byte("\n"))
		for _, s := range strs {
			vals := bytes.Split(s, []byte(":\t"))
			if len(vals) != 2 {
				continue
			}
			k := string(vals[0])
			v := string(vals[1])
			state.ProcStatus[k] = v
		}
	}

    data, err = ioutil.ReadFile("/proc/cpuinfo")
    if err != nil {
        InfoLog.Printf("could not open /proc/cpuinfo: %s", err)
    } else {
		strs := bytes.Split(data, []byte("\n"))
		workingDict := make(map[string]string)
		for _, s := range strs {
			if len(s) == 0 {
				state.ProcCPUInfo = append(state.ProcCPUInfo, workingDict)
				workingDict = make(map[string]string)
				continue
			}

			vals := bytes.SplitN(s, []byte(":"), 2)
			if len(vals) != 2 {
				continue
			}
			k := string(vals[0])
			v := string(vals[1])
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			workingDict[k] = v
		}
		state.ProcCPUInfo = append(state.ProcCPUInfo, workingDict)
	}

	runtime, err := DetectRuntime()
	if err != nil {
		state.Runtime = "not-found"
	} else {
		state.Runtime = runtime
	}

	loadCaps(state)

	state.CgroupPath = "/sys/fs/cgroup"
	devrules, err := ReadDevices(state.CgroupPath + "/devices")
	if err == nil {
		state.CgroupDeviceRules = devrules
	}

	fname := state.CgroupPath + "/cpu/cpu.shares"
    data, err = ioutil.ReadFile(fname)
	if err != nil {
		InfoLog.Printf("error reading %s: %s\n", fname, err)
	} else {
		parsed, err := strconv.ParseUint(string(data[:len(data)-1]), 10, 64)
		if err != nil {
			InfoLog.Printf("error parsing CPU shares: %s: %s\n", data, err)
		}
		state.CgroupCPUShares = parsed
	}

	fname = state.CgroupPath + "/memory/memory.limit_in_bytes"
    data, err = ioutil.ReadFile(fname)
	if err != nil {
		InfoLog.Printf("error reading %s: %s\n", fname, err)
	} else {
		parsed, err := strconv.ParseUint(string(data[:len(data)-1]), 10, 64)
		if err != nil {
			InfoLog.Printf("error parsing memory in bytes: %s: %s\n", data, err)
		}
		state.CgroupMaxMemory = parsed
	}

    return nil
}

type ScanResult struct {
    Title string
    Description string
    Severity SeverityLevel
}

func NewResult(title string, description string, sev SeverityLevel) *ScanResult {
    return &ScanResult{
        Title: title,
        Description: description,
        Severity: sev,
    }
}

func (result *ScanResult) RenderTerm() string {
    s := result.Title + "\n"
	for i:=0; i<len(result.Title); i++ {
		s += "-"
	}
	s += "\n"
    //s += fmt.Sprintf("Severity: %s\n", result.Severity) // Severity is just used for sorting right now
    s += result.Description
    return s
}

func RenderTermResults(results []*ScanResult) {
	sevToRender := []SeverityLevel{SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO}
	for _, sev := range sevToRender {
		for _, result := range results {
			if result.Severity == sev {
				fmt.Println(result.RenderTerm())
				fmt.Println("")
			}
		}
	}
}

func main() {
    curState := NewScanState()

	opts, err := ParseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	curState.CmdOpts = opts

	if curState.CmdOpts.LogFile != "" {
		file, err := os.Create(curState.CmdOpts.LogFile)
		if err != nil {
			fmt.Printf("error opening log file: %s\n", err)
			os.Exit(1)
		}
		InfoLog = log.New(file, "[*] ", 0)
	} else {
		InfoLog = log.New(ioutil.Discard, "[*] ", log.Lshortfile)
	}

    results := make([]*ScanResult, 0)
	
	if (curState.CmdOpts.IPSniffTime > 0) {
		sniffResults, err := SniffIPs(curState, curState.CmdOpts.IPSniffTime)
		if err != nil {
			InfoLog.Printf("error sniffing network: %s\n", err)
		} else {
			results = append(results, sniffResults...)
		}
	} else {
		scanResults, err := NormalScan(curState)
		if err != nil {
			InfoLog.Printf("error performing scan: %s\n", err)
		} else {
			results = append(results, scanResults...)
		}
	}

    // Print results
	RenderTermResults(results)
}

func NormalScan(curState *scanState) ([]*ScanResult, error) {
	var err error
    err = curState.ReadData()
    if err != nil {
        fmt.Printf("error reading data: %s\n", err)
        os.Exit(1)
    }
    results := make([]*ScanResult, 0)

    // Check capabilities
    capresults, err := ScanCaps(curState)
    if err != nil {
        fmt.Printf("error checking caps: %s\n", err.Error())
        os.Exit(1)
    }
    results = append(results, capresults...)

    // mounted dirs/files
    mountresults, err := ScanMounts(curState)
    if err != nil {
        fmt.Printf("error checking scan mounts: %s", err.Error())
        os.Exit(1)
    }
    results = append(results, mountresults...)
    // Character/block devices
    // FDs
    // cgroups
    result, err := ScanCgroups(curState)
    if err != nil {
        fmt.Printf("error scanning cgroups: %s", err.Error())
        os.Exit(1)
    }
    results = append(results, result...)

    // Misc
    result, err = ScanMisc(curState)
    if err != nil {
        fmt.Printf("error with misc scans: %s\n", err.Error())
        os.Exit(1)
    }
    results = append(results, result...)

	return results, nil
}
