package main

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
	"sync"
	"errors"
)
type sender struct {
	src net.IP
	dst net.IP
	dport layers.TCPPort
	sport layers.TCPPort
}

var (
	device       string = "enp8s0"
	snapshot_len int32  = 1516
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func regular() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", ":12345")
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("Hello, World!")); err != nil {
		log.Fatal(err)
	}
}
func main() {
	ping(4)
}

func raw() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Println("error at open")
		log.Fatal(err)
	}
	defer handle.Close()

	// This time lets fill out some information
	ipLayer := &layers.IPv4{
		SrcIP: net.IP{10, 1, 1, 111},
		DstIP: net.IP{10, 1, 1, 1},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	ethernetLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
        SrcMAC:       net.HardwareAddr{0x2c, 0xfd, 0xa1, 0xba, 0x35, 0xcd},
        DstMAC:       net.HardwareAddr{0x12, 0xf5, 0xb1, 0xa4, 0x7b, 0x7e},
	}
	syn := &layers.TCP{
		SYN:     true,
		Window:  14600,
		Seq:     1105024978,
		SrcPort: layers.TCPPort(9576),
		DstPort: layers.TCPPort(888),
	}
	options := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }
    syn.SetNetworkLayerForChecksum(ipLayer)
	/*
	var dstPort int = 53
	rstClose := &layers.TCP{
		RST: true,
		ACK: true,
		//Ack:
		SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(dstPort),
	}
	*/
	// And create the packet with the layers

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		syn,
	)
	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Println("error at write packet")
		log.Fatal(err)
	}
	for {
		reply, _, err := handle.ReadPacketData()
		if err != nil {
			log.Println("error in reply")
			log.Fatal(err)
		}
		//log.Println(reply)
		packet := gopacket.NewPacket(reply, layers.LayerTypeEthernet, gopacket.NoCopy)
		//log.Println(packet)
		var wg sync.WaitGroup
		parsePacket(packet, &wg)
	}
}
func parsePacket(p gopacket.Packet, wg *sync.WaitGroup) {
	if tcpL := p.Layer(layers.LayerTypeTCP); tcpL != nil {
		tcp, ok := tcpL.(*layers.TCP)
		if !ok {
			log.Println("error at TCP parse")
			return
		}
		s := sender{src: net.ParseIP("10.1.1.111"), dport: 888, sport: 9456, dst: net.ParseIP("10.1.1.1") }
		ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
		tcpFlow, err := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(s.dport),layers.NewTCPPortEndpoint(s.sport))
		if err != nil {
			log.Println("error establishing endpoints based on the ports used")
		}
		
		if tcp.TransportFlow() == tcpFlow {
			log.Println("first class success")
		} else if tcp.SYN && tcp.ACK && tcp.DstPort != s.sport  {
			log.Println("second class success")
		} else if tcp.TransportFlow() == ipFlow {
			log.Println("third class success")
		} else if tcp.FIN {
			log.Println("fin")
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			log.Println("ack and payload empty")
		} else if tcp.RST {
			log.Println("closed")
		} else {
			// data packet
				log.Printf("data %s", tcpL)
			}
		}
	}
func ping(count int) {
	s := sender{src: net.ParseIP("10.1.1.111"), dport: 8, dst: net.ParseIP("10.1.1.1") }
	ip := &layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
		Version:  4,
		TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
	}
	ethernetLayer := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
        SrcMAC:       net.HardwareAddr{0x2c, 0xfd, 0xa1, 0xba, 0x35, 0xcd},
        DstMAC:       net.HardwareAddr{0x12, 0xf5, 0xb1, 0xa4, 0x7b, 0x7e},
	}
	rawMagic := []byte("this is a test")
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	handle, err := pcap.OpenLive(
		"enp8s0", // device
		int32(65535),
		false,
		30 * time.Second,
	)
	defer handle.Close()
	if err != nil {
		log.Println("Open handle error", err.Error())
	}
	var complete time.Duration
	ipFlow, err := gopacket.FlowFromEndpoints(layers.NewIPEndpoint(s.dst), layers.NewIPEndpoint(s.src))
	if err != nil {
		log.Println("error establishing endpoints based on the ports used")
	}
	for i := 1; i <= count; i++ {
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id: 2,
			Seq: uint16(i),
		}
		if err := gopacket.SerializeLayers(buf, opts,ethernetLayer, ip, icmp, gopacket.Payload(rawMagic)); err != nil {
			log.Fatal(err)
		}

		log.Printf("I am the count! %d na na na", i)
		start := time.Now()
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			log.Println("Send error", err.Error())
		}
		for {
			reply, _, err := handle.ReadPacketData()
			if err != nil {
				log.Println("found error while waiting for reply")
				log.Println(err)
			}
			p := gopacket.NewPacket(reply, layers.LayerTypeEthernet, gopacket.NoCopy)
			//ipFlow := gopacket.FlowFromEndpoints(layers.EndpointIPv4, s.dst, s.src)
			netL := p.NetworkLayer()
			if time.Since(start) > time.Second*5 {
				newErr := errors.New("time exceeded")
				log.Println(newErr)
				break
			} else if netL != nil {
				if netL.NetworkFlow() == ipFlow && p.Layer(layers.LayerTypeICMPv4) != nil  {
					complete = time.Duration(time.Since(start))
					log.Printf("%+v", p.Layer(layers.LayerTypeIPv4))
					log.Println("second class success")
					break
				}
			}
		}
		log.Println(complete)
		time.Sleep(1 * time.Second)
	}
}
