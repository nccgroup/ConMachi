package main

import(
	"net"
	"strings"
	"time"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

import "C"

func SniffIPs(state *scanState, sniffTime int) ([]*ScanResult, error) {
    results := make([]*ScanResult, 0)
	allInterfaces, err := net.Interfaces()
	if err != nil {
		InfoLog.Printf("error getting interfaces: %s\n", err)
		InfoLog.Println("skipping network scans")
		return results, nil
	}
	interfaces := make([]net.Interface, 0)
	InfoLog.Println("Container has following interfaces:")
	for _, i := range allInterfaces {
		InfoLog.Println(i)
		if i.Flags & net.FlagLoopback == 0 {
			interfaces = append(interfaces, i)
		} else {
			InfoLog.Println("loopback interface, not using in scans")
		}
	}
	InfoLog.Println(interfaces)


	// Set up the timer
	InfoLog.Println("Sniffing for packets...")
	packetsSniffed := 0
	timeout := make(chan bool, 1)
	go func() {
		maxtime := sniffTime
		lastPrintLen := 0
		for i:=0; i<maxtime; i++ {
			toprint := fmt.Sprintf("Time Remaining: %d, %d packets sniffed", maxtime-i, packetsSniffed)
			fmt.Printf("\r%s\r", strings.Repeat(" ", lastPrintLen))
			fmt.Printf("%s", toprint)
			lastPrintLen = len(toprint)
			time.Sleep(time.Second)
		}
		fmt.Printf("\n")
		close(timeout)
	}()

	ipResults := make(map[string]chan string)
	for _, iface := range interfaces {
		ifaceResults := make(chan string, 1)
		ipResults[iface.Name] = ifaceResults
		go func(iface net.Interface, counter *int, results chan string) {
			InfoLog.Printf("sniffing on %s...\n", iface.Name)
			ips := make(map[string]bool)
			handle, err := pcap.OpenLive(iface.Name, 1024, true, 100 * time.Second)
			if err != nil {
				InfoLog.Printf("error opening handle to sniff interface: %s\n", err)
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packChan := packetSource.Packets()

			done := false
			for !done {
				select {
				case packet := <-packChan:
					netFlow := packet.NetworkLayer().NetworkFlow()
					src, dst := netFlow.Endpoints()
					ips[src.String()] = true
					ips[dst.String()] = true
					InfoLog.Printf("packet: src=%s, dst=%s\n", src, dst)
					*counter += 1
				case <-timeout:
					InfoLog.Println("Quitting sniffing")
					done = true
					for k, _ := range ips {
						results <- k
					}
					close(results)
				}
			}
			InfoLog.Println("Closing interface handle...")
			InfoLog.Println("Closed")
		}(iface, &packetsSniffed, ifaceResults)
	}

	// Wait on all interfaces
	InfoLog.Println("Sniffers started, waiting for timeout")
	<-timeout
	InfoLog.Println("Timeout reached, collecting results")

	desc := ""
	for k, result := range ipResults {
		ipList := make([]string, 0)
		for ip := range result {
			ipList = append(ipList, "* " + ip)
		}
		if len(ipList) > 0 {
			desc += fmt.Sprintf("IPs discovered on %s:\n", k)
			desc += strings.Join(ipList, "\n")
			desc += "\n"
		} else {
			desc += fmt.Sprintf("No packets sniffed on %s\n", k)
		}
	}

	result := NewResult("Sniffed IP Addresses", desc, SEV_INFO)
	results = append(results, result)
	return results, nil
}

