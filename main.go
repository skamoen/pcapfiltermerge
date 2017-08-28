package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	pb "gopkg.in/cheggaaa/pb.v2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	filter *string
)

func main() {
	path := flag.String("path", "./", "Path to be scanned for pcaps")
	// filter = flag.String("filter", "tcp[tcpflags] == tcp-syn and tcp dst port 23", "Filter to apply to the pcaps")
	filter = flag.String("filter", "tcp", "Filter to apply to the pcaps")
	output := flag.String("out", "output", "Output file name")
	flag.Parse()

	files, err := ioutil.ReadDir(*path)
	if err != nil {
		fmt.Errorf("Cant read dir %s", *path)
		// do something
	}

	// Open output pcap file and write header
	f, _ := os.Create(*output)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	// Rename to pcap afterwards to prevent processing
	defer os.Rename(*output, *output+".pcap")
	defer f.Close()

	bar := pb.New(len(files))
	bar.Start()
	defer bar.Finish()

	for _, f := range files {
		// Only process pcap files
		if name := filepath.Ext(f.Name()); name == ".pcap" {
			packets := filterPcap(*path + f.Name())
			bar.Increment()
			for _, packet := range packets {
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}
		} else {
			bar.Increment()
		}
	}
}

func filterPcap(file string) []gopacket.Packet {
	//TODO: Check if file exists
	handle, err := pcap.OpenOffline(file)
	if err != nil {
		fmt.Errorf("couldn't open pcap", err)
	}

	var packets []gopacket.Packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	handle.SetBPFFilter(*filter)

	for packet := range packetSource.Packets() {
		packets = append(packets, packet)
	}
	return packets
}