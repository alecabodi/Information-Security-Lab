package main

import (
	"fmt"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
	spath "github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
// Global constants
)

var (
	ipmap        map[string]int      = make(map[string]int)
	IAmap        map[string]int      = make(map[string]int)
	mymap        map[string][]string = make(map[string][]string)
	whitelist    map[string]string   = make(map[string]string)
	ipblacklist  map[string]int      = make(map[string]int)
	ipblacklist2 map[string]int      = make(map[string]int)
	IAblacklist  map[string]int      = make(map[string]int)
	moment       map[string]int      = make(map[string]int)
	def1         bool                = false
	def2         bool                = false
	def12        bool                = false
	def3         bool                = false
	decided      bool                = false
	counter      int                 = 0
	def2_moment  int                 = 0
)

// This function receives all packets destined to the customer server.
//
// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
//   - SCION header
//     https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
//   - UDP header
//     https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP
func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	// Print packet contents (disable this before submitting your code)
	prettyPrintSCION(scion)
	prettyPrintUDP(udp)

	src, _ := scion.SrcAddr()
	_, ok := ipmap[src.String()]
	if !ok {
		ipmap[src.String()] = 1
	} else {
		ipmap[src.String()]++
	}

	_, ok2 := IAmap[scion.SrcIA.String()]
	if !ok2 {
		IAmap[scion.SrcIA.String()] = 1
	} else {
		IAmap[scion.SrcIA.String()]++
	}

	raw := make([]byte, scion.Path.Len())
	scion.Path.SerializeTo(raw)
	path := &spath.Decoded{}
	path.DecodeFromBytes(raw)

	hop := path.HopFields

	// // Print in table format
	// for i, info := range path.InfoFields {
	// 	s += fmt.Sprintf("InfoFields[%d] : ", i) + fmt.Sprintf("{Peer: %v, SegID: %d, Timestamp: %v}", info.Peer, info.SegID, info.Timestamp)
	// }

	// mymap[src.String()] = append(mymap[src.String()], s)

	if ipmap[src.String()] > 1 {
		if ipmap[src.String()] == 2 {
			moment[src.String()] = counter
		}
		whitelist[src.String()] = fmt.Sprintf("{#req: %d, moment: %d", ipmap[src.String()], moment[src.String()])
	}

	counter++

	fmt.Println(ipmap)
	fmt.Println(IAmap)
	fmt.Println(whitelist)
	fmt.Println(IAblacklist)
	fmt.Println(ipblacklist)
	fmt.Println(counter)
	fmt.Println(ipblacklist2)
	fmt.Println(mymap)

	if len(whitelist) > 0 && counter < 9 {
		def12 = true
		fmt.Println("\nD12\n")
	}

	if counter >= 9 && def12 == false {
		def3 = true
		fmt.Println("\nDEF 3\n")
	}

	if def12 == true {

		if ipmap[src.String()] > 6 && counter < 30 && !decided {
			fmt.Println("\nDEF 1\n")
			def1 = true
			decided = true
			ipblacklist[src.String()] = 1
		} else if !decided && counter > 30 {
			fmt.Println("\nDEF 2\n")
			def2 = true
			def2_moment = counter
			decided = true
		}

		if !decided {
			if ipmap[src.String()] > 1 {
				ipblacklist2[src.String()] = 1
			}
		}

		if def1 == true {
			_, blackip := ipblacklist[src.String()]
			if blackip {
				mymap[src.String()+" "] = append(mymap[src.String()+" "], fmt.Sprintf(" : refuse by blackip() %d", counter))
				return false
			}

			if ipmap[src.String()] > 16 {
				mymap[src.String()+" "] = append(mymap[src.String()+" "], fmt.Sprintf(" : refuse by ipmap> %d", counter))
				return false
			}

			_, blackip2 := ipblacklist2[src.String()]
			if blackip2 {
				mymap[src.String()+" "] = append(mymap[src.String()+" "], fmt.Sprintf(" : refuse by blackip2() %d", counter))
				return false
			}

			mymap[src.String()+" "] = append(mymap[src.String()+" "], fmt.Sprintf(" : accept by finDEF1 %d", counter))
			return true
		}

		if def2 == true {
			if IAmap[scion.SrcIA.String()] > 10 && counter < def2_moment+5 {
				IAblacklist[scion.SrcIA.String()] = 1
			}

			_, blackIA := IAblacklist[scion.SrcIA.String()]
			if blackIA {
				mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : refuse by blackIA %d", counter))
				return false
			}

			if ipmap[src.String()] > 6 {
				mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : accept by ipmap> %d", counter))
				return true
			}

			_, blackip2 := ipblacklist2[src.String()]
			if blackip2 {
				mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : refuse by blackip2(DEF2) %d", counter))
				return false
			}

			mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : accept by finDEF2 %d", counter))
			return true

		}

		_, blackip2 := ipblacklist2[src.String()]
		if blackip2 {
			mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : refuse by blackip2() %d", counter))
			return false
		}

		mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : accept by fin12 %d", counter))
		return true
	}

	_, flag := whitelist[src.String()]
	if flag {
		mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : accept by flag %d", counter))
		return true
	}

	if len(whitelist) == 4 || counter > 120 {
		mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : refuse by whitelist %d", counter))
		return flag
	}

	if def3 == true {

		if hop[0].ConsIngress == 0 && hop[0].ConsEgress == 0 {
			return true
		}

		if hop[0].ConsIngress == 1 && hop[0].ConsEgress == 0 {
			return true
		}

		if hop[0].ConsIngress == 1 && hop[0].ConsEgress == 2 {
			return true
		}

		if hop[0].ConsIngress == 4 && hop[0].ConsEgress == 1 {
			return true
		}

		if hop[0].ConsIngress == 4 && hop[0].ConsEgress == 2 {
			return true
		}

		if hop[0].ConsIngress == 4 && hop[0].ConsEgress == 3 {
			return true
		}

		return false
	}

	// // DEF 2
	// if IAmap[scion.SrcIA.String()] > 31 && ipmap[src.String()] < 7 {
	// 	return false
	// }

	// if ipmap[src.String()] > 40 {
	// 	drop_first_packets = false
	// }

	// if udp.Checksum > 10000 {
	// 	return false
	// }

	mymap[scion.SrcIA.String()+"  "+src.String()+" "] = append(mymap[scion.SrcIA.String()+"  "+src.String()+" "], fmt.Sprintf(" : accept by final %d", counter))
	return true
}

func init() {
	// Perform any initial setup here
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
