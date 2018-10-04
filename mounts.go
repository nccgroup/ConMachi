package main

import (
    "fmt"
	"io/ioutil"
	"strings"
	"strconv"
	"bytes"
)


type MountPoint struct {
	Device string
	Path   string
	Type   string
	Opts   []string
	Freq   int
	Pass   int
}

const (
	procMountsPath = "/proc/mounts"
	expectedNumFieldsPerLine = 6
)

var flagMountTypes []string = []string{"adfs", "affs", "autofs", "cifs", "coda", "coherent", "cramfs", /*"debugfs",*/ /*"devpts",*/ "efs", "ext", "ext2", "ext3", "ext4", "hfs", "hfsplus", "hpfs", "iso9660", "jfs", "minix", "msdos", "ncpfs", "nfs", "nfs4", "ntfs", /*"proc",*/ "qnx4", "ramfs", "reiserfs", "romfs", "squashfs", "smbfs", "sysv", /*"tmpfs",*/ "ubifs", "udf", "ufs", "umsdos", "usbfs", "vfat", "xenix", "xfs", "xiafs"} // taken from mount manpage

func listProcMounts() ([]MountPoint, error) {
	content, err := ioutil.ReadFile(procMountsPath)
	if err != nil {
		return nil, err
	}
	return parseProcMounts(content)
}

func parseProcMounts(content []byte) ([]MountPoint, error) {
	out := []MountPoint{}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			// the last split() item is empty string following the last \n
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != expectedNumFieldsPerLine {
			return nil, fmt.Errorf("wrong number of fields (expected %d, got %d): %s", expectedNumFieldsPerLine, len(fields), line)
		}

		mp := MountPoint{
			Device: fields[0],
			Path:   fields[1],
			Type:   fields[2],
			Opts:   strings.Split(fields[3], ","),
		}

		freq, err := strconv.Atoi(fields[4])
		if err != nil {
			return nil, err
		}
		mp.Freq = freq

		pass, err := strconv.Atoi(fields[5])
		if err != nil {
			return nil, err
		}
		mp.Pass = pass

		out = append(out, mp)
	}
	return out, nil
}

func ShouldIgnoreMount(mountPoint MountPoint) bool {
	for _, mtype := range flagMountTypes {
		if mountPoint.Type == mtype {
			return false
		}
	}
	return true
}

func AddToOutput(mountPoint MountPoint, outputBuffer *bytes.Buffer) (error) {

	_, err := outputBuffer.WriteString(fmt.Sprintf("Device: %s\n", mountPoint.Device))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	_, err = outputBuffer.WriteString(fmt.Sprintf("Path: %s\n", mountPoint.Path))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	_, err = outputBuffer.WriteString(fmt.Sprintf("Type: %s\n", mountPoint.Type))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	_, err = outputBuffer.WriteString(fmt.Sprintf("Opts: %v\n", mountPoint.Opts))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	_, err = outputBuffer.WriteString(fmt.Sprintf("Freq: %d\n", mountPoint.Freq))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	_, err = outputBuffer.WriteString(fmt.Sprintf("Pass: %d\n", mountPoint.Pass))
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	} 
	_, err = outputBuffer.WriteString("---\n")
	if err != nil {
		return fmt.Errorf("Error writing to buffer: %s", err)
	}
	return nil
}

func CreateDescriptionFromMountPointList(mountPointList *[]MountPoint, outputBuffer *bytes.Buffer) (error){
	
	var numVulnerableMountPoints = 0
	for _, mountPointIter := range *mountPointList {
		AddToOutput(mountPointIter, outputBuffer)
		numVulnerableMountPoints += 1
	} 
	if numVulnerableMountPoints == 0 {
		return fmt.Errorf("No vulnerable mountpoints available to create description from.")
	}
	return nil
}


func ScanMounts(state *scanState) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0)
	mountPoints, err := listProcMounts()
	if err != nil {
		InfoLog.Printf("error parsing mount info, bailing on scanning mounts: %s", err)
		return results, nil
	}

	writeable := []MountPoint{}
	readable := []MountPoint{}

    for _, mountPointIter := range mountPoints {
		if ShouldIgnoreMount(mountPointIter) {
			continue
		}

    	if mountPointIter.Opts[0] == "rw" {
    		writeable = append(writeable, mountPointIter)
    	}
    	if mountPointIter.Opts[0] == "ro" {
    		readable = append(readable, mountPointIter)
    	}
    }

    var output bytes.Buffer

	if (len(writeable) > 0) {
		err = CreateDescriptionFromMountPointList(&writeable, &output)   
		if err == nil {
			desc := "Some paths are mounted with write permission and may be filesystems mounted from the host. If this is the case, modifying the files at these paths may allow a contained process to modify files outside of the contained environment. The following paths were detected to be mounted with write permissions:\n---\n"
			desc += output.String()
			ret := NewResult("Writeable Mounts", desc, SEV_MEDIUM)
			results = append(results, ret)
			output.Reset()
		}
	}

	if (len(readable) > 0) {
		CreateDescriptionFromMountPointList(&readable, &output)
		if err == nil {  
			desc := "Some paths are mounted with read permission and may be filesystems mounted from the host. If this is the case, reading the files at the following paths may allow a contained process to read files from the host. The following paths were detected to be mounted with read permissions:\n---\n"
			desc += output.String()
			ret := NewResult("Readable Mounts", desc, SEV_LOW)
		    results = append(results, ret)
		    //OUTPUT.RESET() HERE IF YOU'RE GOING TO ADD MORE RESULTS
		}
	}

    return results, nil
}
