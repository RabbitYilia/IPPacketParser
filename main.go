package main

import (
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
)

func main() {
	data, _ := hex.DecodeString("60000000003200ff240c0000000000000000000000000001240c00000000000000000000000000023c0001040000000000000104000000002b000104000000003a000000000000008000f1510000000041414141414141414141")
	IPversion := data[0] >> 4
	switch IPversion {
	case 4:
		IPv4Packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Lazy)
		ProcessIPv4(IPv4Packet)
	case 6:
		IPv6Packet := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Lazy)
		ProcessIPv6(IPv6Packet)
	}
}

func ProcessIPv6(v6Packet gopacket.Packet) {
	var ParsedLayers []map[string]interface{}
	Layers := v6Packet.Layers()
	for LayerNum, Layer := range Layers {
		switch Layer.LayerType() {
		case layers.LayerTypeIPv6:
			thisLayer := make(map[string]interface{})
			IPv6Layer := Layer.(*layers.IPv6)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Version"] = IPv6Layer.Version
			thisLayer["SrcIP"] = IPv6Layer.SrcIP.String()
			thisLayer["DstIP"] = IPv6Layer.DstIP.String()
			thisLayer["HopLimit"] = IPv6Layer.HopLimit
			thisLayer["FlowLabel"] = IPv6Layer.FlowLabel
			thisLayer["TrafficClass"] = IPv6Layer.TrafficClass
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPv6HopByHop:
			thisLayer := make(map[string]interface{})
			IPv6HopByHopLayer := Layer.(*layers.IPv6HopByHop)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			var optionsmap []map[string]interface{}
			for _, thisoption := range IPv6HopByHopLayer.Options {
				thisoptionmap := make(map[string]interface{})
				thisoptionmap["Type"] = thisoption.OptionType
				thisoptionmap["Data"] = thisoption.OptionData
				optionsmap = append(optionsmap, thisoptionmap)
			}
			thisLayer["Options"] = optionsmap
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPv6Routing:
			thisLayer := make(map[string]interface{})
			IPv6RoutingLayer := Layer.(*layers.IPv6Routing)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["RoutingType"] = IPv6RoutingLayer.RoutingType
			thisLayer["Reserved"] = IPv6RoutingLayer.Reserved
			var SourceRoutingIPs []string
			for _, thisIP := range IPv6RoutingLayer.SourceRoutingIPs {
				SourceRoutingIPs = append(SourceRoutingIPs, thisIP.String())
			}
			thisLayer["SourceRoutingIPs"] = SourceRoutingIPs
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPv6Destination:
			thisLayer := make(map[string]interface{})
			IPv6DestinationLayer := Layer.(*layers.IPv6Destination)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			var optionsmap []map[string]interface{}
			for _, thisoption := range IPv6DestinationLayer.Options {
				thisoptionmap := make(map[string]interface{})
				thisoptionmap["Type"] = thisoption.OptionType
				thisoptionmap["Data"] = thisoption.OptionData
				optionsmap = append(optionsmap, thisoptionmap)
			}
			thisLayer["Options"] = optionsmap
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPv6Fragment:
			thisLayer := make(map[string]interface{})
			IPv6FragmentLayer := Layer.(*layers.IPv6Fragment)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["RawData"] = IPv6FragmentLayer.LayerContents()
			thisLayer["FragmentOffset"] = IPv6FragmentLayer.FragmentOffset
			thisLayer["Identification"] = IPv6FragmentLayer.Identification
			thisLayer["MoreFragments"] = IPv6FragmentLayer.MoreFragments
			thisLayer["Reserved1"] = IPv6FragmentLayer.Reserved1
			thisLayer["Reserved2"] = IPv6FragmentLayer.Reserved2
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeUDP:
			thisLayer := make(map[string]interface{})
			UDPLayer := Layer.(*layers.UDP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SrcPort"] = uint8(UDPLayer.SrcPort)
			thisLayer["DstPort"] = uint8(UDPLayer.DstPort)
			thisLayer["Checksum"] = UDPLayer.Checksum
			thisLayer["Length"] = UDPLayer.Length
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeTCP:
			thisLayer := make(map[string]interface{})
			TCPLayer := Layer.(*layers.TCP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SrcPort"] = uint8(TCPLayer.SrcPort)
			thisLayer["DstPort"] = uint8(TCPLayer.DstPort)
			thisLayer["Seq"] = TCPLayer.Seq
			thisLayer["Ack"] = TCPLayer.Ack
			thisLayer["DataOffset"] = TCPLayer.DataOffset
			thisLayer["NS"] = TCPLayer.NS
			thisLayer["CWR"] = TCPLayer.CWR
			thisLayer["ECE"] = TCPLayer.ECE
			thisLayer["URG"] = TCPLayer.URG
			thisLayer["ACK"] = TCPLayer.ACK
			thisLayer["PSH"] = TCPLayer.PSH
			thisLayer["RST"] = TCPLayer.RST
			thisLayer["SYN"] = TCPLayer.SYN
			thisLayer["FIN"] = TCPLayer.FIN
			thisLayer["Window"] = TCPLayer.Window
			thisLayer["Checksum"] = TCPLayer.Checksum
			thisLayer["Urgent"] = TCPLayer.Urgent
			thisLayer["Padding"] = TCPLayer.Padding
			var optionsmap []map[string]interface{}
			for _, thisoption := range TCPLayer.Options {
				thisoptionmap := make(map[string]interface{})
				thisoptionmap["Type"] = thisoption.OptionType
				thisoptionmap["Data"] = thisoption.OptionData
				optionsmap = append(optionsmap, thisoptionmap)
			}
			thisLayer["Options"] = optionsmap
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6:
			thisLayer := make(map[string]interface{})
			ICMPv6Layer := Layer.(*layers.ICMPv6)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["ICMPType"] = ICMPv6Layer.TypeCode.Type()
			thisLayer["ICMPCode"] = ICMPv6Layer.TypeCode.Code()
			thisLayer["Checksum"] = ICMPv6Layer.Checksum
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6Echo:
			thisLayer := make(map[string]interface{})
			ICMPv6EchoLayer := Layer.(*layers.ICMPv6Echo)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SeqNumber"] = ICMPv6EchoLayer.SeqNumber
			thisLayer["Identifier"] = ICMPv6EchoLayer.Identifier
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6NeighborAdvertisement:
			thisLayer := make(map[string]interface{})
			ICMPv6NALayer := Layer.(*layers.ICMPv6NeighborAdvertisement)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["TargetAddress"] = ICMPv6NALayer.TargetAddress.String()
			thisLayer["Flags"] = ICMPv6NALayer.Flags
			thisLayer["Options"] = ICMPv6NALayer.Options
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6NeighborSolicitation:
			thisLayer := make(map[string]interface{})
			ICMPv6NSLayer := Layer.(*layers.ICMPv6NeighborSolicitation)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["TargetAddress"] = ICMPv6NSLayer.TargetAddress.String()
			thisLayer["Options"] = ICMPv6NSLayer.Options
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6RouterAdvertisement:
			thisLayer := make(map[string]interface{})
			ICMPv6RALayer := Layer.(*layers.ICMPv6RouterAdvertisement)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["RouterLifetime"] = ICMPv6RALayer.RouterLifetime
			thisLayer["RetransTimer"] = ICMPv6RALayer.RetransTimer
			thisLayer["ReachableTime"] = ICMPv6RALayer.ReachableTime
			thisLayer["Flags"] = ICMPv6RALayer.Flags
			thisLayer["HopLimit"] = ICMPv6RALayer.HopLimit
			thisLayer["Options"] = ICMPv6RALayer.Options
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6RouterSolicitation:
			thisLayer := make(map[string]interface{})
			ICMPv6RSLayer := Layer.(*layers.ICMPv6RouterSolicitation)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Options"] = ICMPv6RSLayer.Options
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv6Redirect:
			thisLayer := make(map[string]interface{})
			ICMPv6Redirect := Layer.(*layers.ICMPv6Redirect)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["TargetAddress"] = ICMPv6Redirect.TargetAddress.String()
			thisLayer["DestinationAddress"] = ICMPv6Redirect.DestinationAddress.String()
			thisLayer["Options"] = ICMPv6Redirect.Options
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeDHCPv6:
			thisLayer := make(map[string]interface{})
			DHCPv6 := Layer.(*layers.DHCPv6)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["TransactionID"] = DHCPv6.TransactionID
			thisLayer["PeerAddr"] = DHCPv6.PeerAddr.String()
			thisLayer["LinkAddr"] = DHCPv6.LinkAddr.String()
			thisLayer["HopCount"] = DHCPv6.HopCount
			thisLayer["MsgType"] = DHCPv6.MsgType.String()
			thisLayer["Options"] = DHCPv6.Options.String()
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeDNS:
			thisLayer := make(map[string]interface{})
			DNS := Layer.(*layers.DNS)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["ID"] = DNS.ID
			thisLayer["Z"] = DNS.Z
			thisLayer["AA"] = DNS.AA
			thisLayer["QR"] = DNS.QR
			thisLayer["RA"] = DNS.RA
			thisLayer["RD"] = DNS.RD
			thisLayer["TC"] = DNS.TC
			thisLayer["ANCount"] = DNS.ANCount
			thisLayer["ARCount"] = DNS.ARCount
			thisLayer["NSCount"] = DNS.NSCount
			thisLayer["QDCount"] = DNS.QDCount
			thisLayer["ResponseCode"] = DNS.ResponseCode.String()
			thisLayer["OpCode"] = DNS.OpCode.String()
			var Additionals []map[string]interface{}
			for _, Additional := range DNS.Additionals {
				thisAdditional := make(map[string]interface{})
				thisAdditional["RecordType"] = Additional.Type.String()
				thisAdditional["NS"] = Additional.NS
				thisAdditional["IP"] = Additional.IP.String()
				thisAdditional["Data"] = Additional.Data
				thisAdditional["Class"] = Additional.Class.String()
				thisAdditional["CNAME"] = Additional.CNAME
				thisAdditional["DataLength"] = Additional.DataLength
				thisAdditional["MX-NAME"] = Additional.MX.Name
				thisAdditional["MX-Preference"] = Additional.MX.Preference
				thisAdditional["Name"] = Additional.Name
				thisAdditional["PTR"] = Additional.PTR
				thisAdditional["SOA-Expire"] = Additional.SOA.Expire
				thisAdditional["SOA-Minimum"] = Additional.SOA.Minimum
				thisAdditional["SOA-MName"] = Additional.SOA.MName
				thisAdditional["SOA-Refresh"] = Additional.SOA.Refresh
				thisAdditional["SOA-Retry"] = Additional.SOA.Retry
				thisAdditional["SOA-RName"] = Additional.SOA.RName
				thisAdditional["SOA-Serial"] = Additional.SOA.Serial
				thisAdditional["SRV-Name"] = Additional.SRV.Name
				thisAdditional["SRV-Port"] = Additional.SRV.Port
				thisAdditional["SRV-Priority"] = Additional.SRV.Priority
				thisAdditional["SRV-Weight"] = Additional.SRV.Weight
				thisAdditional["TTL"] = Additional.TTL
				thisAdditional["TXT"] = Additional.TXT
				var TXTs [][]byte
				for _, TXT := range Additional.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAdditional["TXTs"] = TXTs
				Additionals = append(Additionals, thisAdditional)
			}
			thisLayer["Additionals"] = Additionals
			var Answers []map[string]interface{}
			for _, Answer := range DNS.Answers {
				thisAnswer := make(map[string]interface{})
				thisAnswer["RecordType"] = Answer.Type.String()
				thisAnswer["NS"] = Answer.NS
				thisAnswer["IP"] = Answer.IP.String()
				thisAnswer["Data"] = Answer.Data
				thisAnswer["Class"] = Answer.Class.String()
				thisAnswer["CNAME"] = Answer.CNAME
				thisAnswer["DataLength"] = Answer.DataLength
				thisAnswer["MX-NAME"] = Answer.MX.Name
				thisAnswer["MX-Preference"] = Answer.MX.Preference
				thisAnswer["Name"] = Answer.Name
				thisAnswer["PTR"] = Answer.PTR
				thisAnswer["SOA-Expire"] = Answer.SOA.Expire
				thisAnswer["SOA-Minimum"] = Answer.SOA.Minimum
				thisAnswer["SOA-MName"] = Answer.SOA.MName
				thisAnswer["SOA-Refresh"] = Answer.SOA.Refresh
				thisAnswer["SOA-Retry"] = Answer.SOA.Retry
				thisAnswer["SOA-RName"] = Answer.SOA.RName
				thisAnswer["SOA-Serial"] = Answer.SOA.Serial
				thisAnswer["SRV-Name"] = Answer.SRV.Name
				thisAnswer["SRV-Port"] = Answer.SRV.Port
				thisAnswer["SRV-Priority"] = Answer.SRV.Priority
				thisAnswer["SRV-Weight"] = Answer.SRV.Weight
				thisAnswer["TTL"] = Answer.TTL
				thisAnswer["TXT"] = Answer.TXT
				var TXTs [][]byte
				for _, TXT := range Answer.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAnswer["TXTs"] = TXTs
				Answers = append(Answers, thisAnswer)
			}
			thisLayer["Answers"] = Answers
			thisLayer["Additionals"] = Additionals
			var Authorities []map[string]interface{}
			for _, Authoritie := range DNS.Authorities {
				thisAuthoritie := make(map[string]interface{})
				thisAuthoritie["RecordType"] = Authoritie.Type.String()
				thisAuthoritie["NS"] = Authoritie.NS
				thisAuthoritie["IP"] = Authoritie.IP.String()
				thisAuthoritie["Data"] = Authoritie.Data
				thisAuthoritie["Class"] = Authoritie.Class.String()
				thisAuthoritie["CNAME"] = Authoritie.CNAME
				thisAuthoritie["DataLength"] = Authoritie.DataLength
				thisAuthoritie["MX-NAME"] = Authoritie.MX.Name
				thisAuthoritie["MX-Preference"] = Authoritie.MX.Preference
				thisAuthoritie["Name"] = Authoritie.Name
				thisAuthoritie["PTR"] = Authoritie.PTR
				thisAuthoritie["SOA-Expire"] = Authoritie.SOA.Expire
				thisAuthoritie["SOA-Minimum"] = Authoritie.SOA.Minimum
				thisAuthoritie["SOA-MName"] = Authoritie.SOA.MName
				thisAuthoritie["SOA-Refresh"] = Authoritie.SOA.Refresh
				thisAuthoritie["SOA-Retry"] = Authoritie.SOA.Retry
				thisAuthoritie["SOA-RName"] = Authoritie.SOA.RName
				thisAuthoritie["SOA-Serial"] = Authoritie.SOA.Serial
				thisAuthoritie["SRV-Name"] = Authoritie.SRV.Name
				thisAuthoritie["SRV-Port"] = Authoritie.SRV.Port
				thisAuthoritie["SRV-Priority"] = Authoritie.SRV.Priority
				thisAuthoritie["SRV-Weight"] = Authoritie.SRV.Weight
				thisAuthoritie["TTL"] = Authoritie.TTL
				thisAuthoritie["TXT"] = Authoritie.TXT
				var TXTs [][]byte
				for _, TXT := range Authoritie.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAuthoritie["TXTs"] = TXTs
				Answers = append(Answers, thisAuthoritie)
			}
			thisLayer["Authorities"] = Authorities
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPSecAH:
			thisLayer := make(map[string]interface{})
			IPSecAH := Layer.(*layers.IPSecAH)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SPI"] = IPSecAH.SPI
			thisLayer["Seq"] = IPSecAH.Seq
			thisLayer["Reserved"] = IPSecAH.Reserved
			thisLayer["AuthenticationData"] = IPSecAH.AuthenticationData
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPSecESP:
			thisLayer := make(map[string]interface{})
			IPSecESP := Layer.(*layers.IPSecESP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SPI"] = IPSecESP.SPI
			thisLayer["Seq"] = IPSecESP.Seq
			thisLayer["Encrypted"] = IPSecESP.Encrypted
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeUDPLite:
			thisLayer := make(map[string]interface{})
			UDPLite := Layer.(*layers.UDPLite)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Checksum"] = UDPLite.Checksum
			thisLayer["SrcPort"] = UDPLite.SrcPort.String()
			thisLayer["DstPort"] = UDPLite.DstPort.String()
			thisLayer["ChecksumCoverage"] = UDPLite.ChecksumCoverage
			ParsedLayers = append(ParsedLayers, thisLayer)
		default:
			thisLayer := make(map[string]interface{})
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			ParsedLayers = append(ParsedLayers, thisLayer)
		}
	}
	log.Println(ParsedLayers)
}

func ProcessIPv4(v6Packet gopacket.Packet) {
	var ParsedLayers []map[string]interface{}
	Layers := v6Packet.Layers()
	for LayerNum, Layer := range Layers {
		switch Layer.LayerType() {
		case layers.LayerTypeIPv4:
			thisLayer := make(map[string]interface{})
			IPv4Layer := Layer.(*layers.IPv4)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Version"] = IPv4Layer.Version
			thisLayer["IHL"] = IPv4Layer.IHL
			thisLayer["TOS"] = IPv4Layer.TOS
			thisLayer["Length"] = IPv4Layer.Length
			thisLayer["Id"] = IPv4Layer.Id
			thisLayer["Flags"] = IPv4Layer.Flags.String()
			thisLayer["FragOffset"] = IPv4Layer.FragOffset
			thisLayer["TTL"] = IPv4Layer.TTL
			thisLayer["Checksum"] = IPv4Layer.Checksum
			thisLayer["SrcIP"] = IPv4Layer.SrcIP.String()
			thisLayer["DstIP"] = IPv4Layer.DstIP.String()
			thisLayer["DstIP"] = IPv4Layer.Options
			thisLayer["Padding"] = IPv4Layer.Padding
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeICMPv4:
			thisLayer := make(map[string]interface{})
			ICMPv4Layer := Layer.(*layers.ICMPv4)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Checksum"] = ICMPv4Layer.Checksum
			thisLayer["Id"] = ICMPv4Layer.Id
			thisLayer["Seq"] = ICMPv4Layer.Seq
			thisLayer["Type"] = ICMPv4Layer.TypeCode.Type()
			thisLayer["Code"] = ICMPv4Layer.TypeCode.Code()
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeDHCPv4:
			thisLayer := make(map[string]interface{})
			DHCPv4Layer := Layer.(*layers.DHCPv4)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["YourClientIP"] = DHCPv4Layer.YourClientIP.String()
			thisLayer["Xid"] = DHCPv4Layer.Xid
			thisLayer["ServerName"] = DHCPv4Layer.ServerName
			thisLayer["Secs"] = DHCPv4Layer.Secs
			thisLayer["RelayAgentIP"] = DHCPv4Layer.RelayAgentIP.String()
			thisLayer["NextServerIP"] = DHCPv4Layer.NextServerIP.String()
			thisLayer["Operation"] = DHCPv4Layer.Operation.String()
			thisLayer["HardwareType"] = DHCPv4Layer.HardwareType.String()
			thisLayer["HardwareOpts"] = DHCPv4Layer.HardwareOpts
			thisLayer["HardwareLen"] = DHCPv4Layer.HardwareLen
			thisLayer["File"] = DHCPv4Layer.File
			thisLayer["ClientIP"] = DHCPv4Layer.ClientIP.String()
			thisLayer["ClientHWAddr"] = DHCPv4Layer.ClientHWAddr.String()
			thisLayer["Flags"] = DHCPv4Layer.Flags
			thisLayer["Options"] = DHCPv4Layer.Options.String()
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeUDP:
			thisLayer := make(map[string]interface{})
			UDPLayer := Layer.(*layers.UDP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SrcPort"] = uint8(UDPLayer.SrcPort)
			thisLayer["DstPort"] = uint8(UDPLayer.DstPort)
			thisLayer["Checksum"] = UDPLayer.Checksum
			thisLayer["Length"] = UDPLayer.Length
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeTCP:
			thisLayer := make(map[string]interface{})
			TCPLayer := Layer.(*layers.TCP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SrcPort"] = uint8(TCPLayer.SrcPort)
			thisLayer["DstPort"] = uint8(TCPLayer.DstPort)
			thisLayer["Seq"] = TCPLayer.Seq
			thisLayer["Ack"] = TCPLayer.Ack
			thisLayer["DataOffset"] = TCPLayer.DataOffset
			thisLayer["NS"] = TCPLayer.NS
			thisLayer["CWR"] = TCPLayer.CWR
			thisLayer["ECE"] = TCPLayer.ECE
			thisLayer["URG"] = TCPLayer.URG
			thisLayer["ACK"] = TCPLayer.ACK
			thisLayer["PSH"] = TCPLayer.PSH
			thisLayer["RST"] = TCPLayer.RST
			thisLayer["SYN"] = TCPLayer.SYN
			thisLayer["FIN"] = TCPLayer.FIN
			thisLayer["Window"] = TCPLayer.Window
			thisLayer["Checksum"] = TCPLayer.Checksum
			thisLayer["Urgent"] = TCPLayer.Urgent
			thisLayer["Padding"] = TCPLayer.Padding
			var optionsmap []map[string]interface{}
			for _, thisoption := range TCPLayer.Options {
				thisoptionmap := make(map[string]interface{})
				thisoptionmap["Type"] = thisoption.OptionType
				thisoptionmap["Data"] = thisoption.OptionData
				optionsmap = append(optionsmap, thisoptionmap)
			}
			thisLayer["Options"] = optionsmap
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeDNS:
			thisLayer := make(map[string]interface{})
			DNS := Layer.(*layers.DNS)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["ID"] = DNS.ID
			thisLayer["Z"] = DNS.Z
			thisLayer["AA"] = DNS.AA
			thisLayer["QR"] = DNS.QR
			thisLayer["RA"] = DNS.RA
			thisLayer["RD"] = DNS.RD
			thisLayer["TC"] = DNS.TC
			thisLayer["ANCount"] = DNS.ANCount
			thisLayer["ARCount"] = DNS.ARCount
			thisLayer["NSCount"] = DNS.NSCount
			thisLayer["QDCount"] = DNS.QDCount
			thisLayer["ResponseCode"] = DNS.ResponseCode.String()
			thisLayer["OpCode"] = DNS.OpCode.String()
			var Additionals []map[string]interface{}
			for _, Additional := range DNS.Additionals {
				thisAdditional := make(map[string]interface{})
				thisAdditional["RecordType"] = Additional.Type.String()
				thisAdditional["NS"] = Additional.NS
				thisAdditional["IP"] = Additional.IP.String()
				thisAdditional["Data"] = Additional.Data
				thisAdditional["Class"] = Additional.Class.String()
				thisAdditional["CNAME"] = Additional.CNAME
				thisAdditional["DataLength"] = Additional.DataLength
				thisAdditional["MX-NAME"] = Additional.MX.Name
				thisAdditional["MX-Preference"] = Additional.MX.Preference
				thisAdditional["Name"] = Additional.Name
				thisAdditional["PTR"] = Additional.PTR
				thisAdditional["SOA-Expire"] = Additional.SOA.Expire
				thisAdditional["SOA-Minimum"] = Additional.SOA.Minimum
				thisAdditional["SOA-MName"] = Additional.SOA.MName
				thisAdditional["SOA-Refresh"] = Additional.SOA.Refresh
				thisAdditional["SOA-Retry"] = Additional.SOA.Retry
				thisAdditional["SOA-RName"] = Additional.SOA.RName
				thisAdditional["SOA-Serial"] = Additional.SOA.Serial
				thisAdditional["SRV-Name"] = Additional.SRV.Name
				thisAdditional["SRV-Port"] = Additional.SRV.Port
				thisAdditional["SRV-Priority"] = Additional.SRV.Priority
				thisAdditional["SRV-Weight"] = Additional.SRV.Weight
				thisAdditional["TTL"] = Additional.TTL
				thisAdditional["TXT"] = Additional.TXT
				var TXTs [][]byte
				for _, TXT := range Additional.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAdditional["TXTs"] = TXTs
				Additionals = append(Additionals, thisAdditional)
			}
			thisLayer["Additionals"] = Additionals
			var Answers []map[string]interface{}
			for _, Answer := range DNS.Answers {
				thisAnswer := make(map[string]interface{})
				thisAnswer["RecordType"] = Answer.Type.String()
				thisAnswer["NS"] = Answer.NS
				thisAnswer["IP"] = Answer.IP.String()
				thisAnswer["Data"] = Answer.Data
				thisAnswer["Class"] = Answer.Class.String()
				thisAnswer["CNAME"] = Answer.CNAME
				thisAnswer["DataLength"] = Answer.DataLength
				thisAnswer["MX-NAME"] = Answer.MX.Name
				thisAnswer["MX-Preference"] = Answer.MX.Preference
				thisAnswer["Name"] = Answer.Name
				thisAnswer["PTR"] = Answer.PTR
				thisAnswer["SOA-Expire"] = Answer.SOA.Expire
				thisAnswer["SOA-Minimum"] = Answer.SOA.Minimum
				thisAnswer["SOA-MName"] = Answer.SOA.MName
				thisAnswer["SOA-Refresh"] = Answer.SOA.Refresh
				thisAnswer["SOA-Retry"] = Answer.SOA.Retry
				thisAnswer["SOA-RName"] = Answer.SOA.RName
				thisAnswer["SOA-Serial"] = Answer.SOA.Serial
				thisAnswer["SRV-Name"] = Answer.SRV.Name
				thisAnswer["SRV-Port"] = Answer.SRV.Port
				thisAnswer["SRV-Priority"] = Answer.SRV.Priority
				thisAnswer["SRV-Weight"] = Answer.SRV.Weight
				thisAnswer["TTL"] = Answer.TTL
				thisAnswer["TXT"] = Answer.TXT
				var TXTs [][]byte
				for _, TXT := range Answer.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAnswer["TXTs"] = TXTs
				Answers = append(Answers, thisAnswer)
			}
			thisLayer["Answers"] = Answers
			thisLayer["Additionals"] = Additionals
			var Authorities []map[string]interface{}
			for _, Authoritie := range DNS.Authorities {
				thisAuthoritie := make(map[string]interface{})
				thisAuthoritie["RecordType"] = Authoritie.Type.String()
				thisAuthoritie["NS"] = Authoritie.NS
				thisAuthoritie["IP"] = Authoritie.IP.String()
				thisAuthoritie["Data"] = Authoritie.Data
				thisAuthoritie["Class"] = Authoritie.Class.String()
				thisAuthoritie["CNAME"] = Authoritie.CNAME
				thisAuthoritie["DataLength"] = Authoritie.DataLength
				thisAuthoritie["MX-NAME"] = Authoritie.MX.Name
				thisAuthoritie["MX-Preference"] = Authoritie.MX.Preference
				thisAuthoritie["Name"] = Authoritie.Name
				thisAuthoritie["PTR"] = Authoritie.PTR
				thisAuthoritie["SOA-Expire"] = Authoritie.SOA.Expire
				thisAuthoritie["SOA-Minimum"] = Authoritie.SOA.Minimum
				thisAuthoritie["SOA-MName"] = Authoritie.SOA.MName
				thisAuthoritie["SOA-Refresh"] = Authoritie.SOA.Refresh
				thisAuthoritie["SOA-Retry"] = Authoritie.SOA.Retry
				thisAuthoritie["SOA-RName"] = Authoritie.SOA.RName
				thisAuthoritie["SOA-Serial"] = Authoritie.SOA.Serial
				thisAuthoritie["SRV-Name"] = Authoritie.SRV.Name
				thisAuthoritie["SRV-Port"] = Authoritie.SRV.Port
				thisAuthoritie["SRV-Priority"] = Authoritie.SRV.Priority
				thisAuthoritie["SRV-Weight"] = Authoritie.SRV.Weight
				thisAuthoritie["TTL"] = Authoritie.TTL
				thisAuthoritie["TXT"] = Authoritie.TXT
				var TXTs [][]byte
				for _, TXT := range Authoritie.TXTs {
					TXTs = append(TXTs, TXT)
				}
				thisAuthoritie["TXTs"] = TXTs
				Answers = append(Answers, thisAuthoritie)
			}
			thisLayer["Authorities"] = Authorities
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPSecAH:
			thisLayer := make(map[string]interface{})
			IPSecAH := Layer.(*layers.IPSecAH)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SPI"] = IPSecAH.SPI
			thisLayer["Seq"] = IPSecAH.Seq
			thisLayer["Reserved"] = IPSecAH.Reserved
			thisLayer["AuthenticationData"] = IPSecAH.AuthenticationData
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeIPSecESP:
			thisLayer := make(map[string]interface{})
			IPSecESP := Layer.(*layers.IPSecESP)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["SPI"] = IPSecESP.SPI
			thisLayer["Seq"] = IPSecESP.Seq
			thisLayer["Encrypted"] = IPSecESP.Encrypted
			ParsedLayers = append(ParsedLayers, thisLayer)
		case layers.LayerTypeUDPLite:
			thisLayer := make(map[string]interface{})
			UDPLite := Layer.(*layers.UDPLite)
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			thisLayer["Checksum"] = UDPLite.Checksum
			thisLayer["SrcPort"] = UDPLite.SrcPort.String()
			thisLayer["DstPort"] = UDPLite.DstPort.String()
			thisLayer["ChecksumCoverage"] = UDPLite.ChecksumCoverage
			ParsedLayers = append(ParsedLayers, thisLayer)
		default:
			thisLayer := make(map[string]interface{})
			thisLayer["LayerNum"] = LayerNum
			thisLayer["Type"] = Layer.LayerType()
			ParsedLayers = append(ParsedLayers, thisLayer)
		}
	}
	log.Println(ParsedLayers)
}
