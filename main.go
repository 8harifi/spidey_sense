package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for index, i := range interfaces {
		fmt.Printf("[%d] %s\n", index+1, i.Description)
	}
	var option int
	_, err = fmt.Scan(&option)
	if err != nil {
		return
	}
	fmt.Println(option)
	fmt.Println(interfaces[option-1])
	iface := interfaces[option-1]

	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet.String())
	}
}
