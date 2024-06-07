package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	eolib_data "github.com/ethanmoffat/eolib-go/v3/data"
	eolib_encrypt "github.com/ethanmoffat/eolib-go/v3/encrypt"
	eolib_packet "github.com/ethanmoffat/eolib-go/v3/packet"
	eolib_net "github.com/ethanmoffat/eolib-go/v3/protocol/net"
	eolib_client "github.com/ethanmoffat/eolib-go/v3/protocol/net/client"
	eolib_server "github.com/ethanmoffat/eolib-go/v3/protocol/net/server"
	"github.com/ethanmoffat/eopcap/dump"
)

type Flags struct {
	ListenHost string
	ListenPort int

	TargetHost string
	TargetPort int

	DataDir string
}

var (
	flags Flags
	wg    sync.WaitGroup

	client_encryption_multiple *int
	server_encryption_multiple *int
	sequence                   eolib_packet.SequenceGetter
	sequencer                  eolib_packet.PacketSequencer
)

func main() {
	flag.StringVar(&flags.ListenHost, "H", "127.0.0.1", "The address to listen on")
	flag.IntVar(&flags.ListenPort, "P", 8078, "The port to listen on")
	flag.StringVar(&flags.TargetHost, "h", "eoserv.moffat.io", "The host to connect to")
	flag.IntVar(&flags.TargetPort, "p", 8078, "The target port to connect to")
	flag.StringVar(&flags.DataDir, "d", "out", "The data directory to where packets should be logged")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	var packet eolib_net.Packet
	packet = &eolib_client.InitInitClientPacket{
		Challenge: 1,
		Version: eolib_net.Version{
			Major: 2,
			Minor: 3,
			Patch: 4,
		},
		Hdid: "567890",
	}
	writer := eolib_data.NewEoWriter()
	packet.Serialize(writer)
	model, _ := dump.Convert(writer.Array(), packet)
	model.Marshal("test.json")

	packet = &eolib_server.EffectPlayerServerPacket{
		Effects: []eolib_server.PlayerEffect{
			{PlayerId: 1, EffectId: 29},
			{PlayerId: 2, EffectId: 28},
			{PlayerId: 3, EffectId: 27},
		},
	}
	writer = eolib_data.NewEoWriter()
	packet.Serialize(writer)
	model, _ = dump.Convert(writer.Array(), packet)
	model.Marshal("test2.json")

	packet = &eolib_server.InitInitServerPacket{
		ReplyCode: eolib_server.InitReply_Banned,
		ReplyCodeData: &eolib_server.InitInitReplyCodeDataBanned{
			BanType: eolib_server.InitBan_Temporary,
			BanTypeData: &eolib_server.InitInitBanTypeDataTemporary{
				MinutesRemaining: 69,
			},
		},
	}
	writer = eolib_data.NewEoWriter()
	packet.Serialize(writer)
	model, _ = dump.Convert(writer.Array(), packet)
	model.Marshal("test3.json")

	packet = &eolib_client.RangeRequestClientPacket{
		PlayerIds:  []int{1, 2, 3, 4, 5},
		NpcIndexes: []int{6, 7, 8, 9, 0},
	}
	writer = eolib_data.NewEoWriter()
	packet.Serialize(writer)
	model, _ = dump.Convert(writer.Array(), packet)
	model.Marshal("test4.json")

	go runProxy(ctx)

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt)
	defer close(interruptChan)

	log.Println("press CTRL+C to quit")
	sig := <-interruptChan
	log.Println("exiting due to signal ::", sig)

	cancel()

	wg.Wait()
}

func runProxy(mainCtx context.Context) {
	var (
		listener net.Listener
		err      error
	)

	wg.Add(1)
	defer wg.Done()

	listenAddr := fmt.Sprintf("%s:%d", flags.ListenHost, flags.ListenPort)
	if listener, err = net.Listen("tcp", listenAddr); err != nil {
		log.Fatalln("failed Listen call :: ", err)
	}
	defer listener.Close()

	log.Println("listening on ::", listenAddr)

	accept := make(chan net.Conn, 1)
	defer close(accept)
	go func(l net.Listener, a chan<- net.Conn) {
		for {
			c, e := listener.Accept()
			if e != nil {
				if _, k := e.(*net.OpError); !k {
					log.Println("failed to accept client connection ::", e)
				} else {
					log.Println("accept loop terminated")
				}
				return
			} else {
				a <- c
			}
		}
	}(listener, accept)

loop:
	for {
		log.Println("waiting for connection...")

		select {
		case <-mainCtx.Done():
			break loop
		case clientConn := <-accept:
			client_encryption_multiple = nil
			server_encryption_multiple = nil
			sequence = eolib_packet.NewZeroSequence()
			sequencer = eolib_packet.NewPacketSequencer(sequence)

			func() {
				var (
					serverConn net.Conn
					err        error
				)

				defer clientConn.Close()

				const MaxAttempts = 5

				connectAddr := fmt.Sprintf("%s:%d", flags.TargetHost, flags.TargetPort)
				for attempt := 1; attempt <= MaxAttempts; attempt++ {
					serverConn, err = net.Dial("tcp4", connectAddr)
					if err != nil {
						log.Printf("error connecting to server (%d/%d) :: %v", attempt, MaxAttempts, err)
						if attempt < MaxAttempts {
							log.Printf("attempting reconnect in %d seconds", attempt*attempt)
							time.Sleep(time.Duration(attempt*attempt) * time.Second)
						} else {
							log.Printf("maximum attempts reached")
							return
						}
					} else {
						break
					}
				}
				defer serverConn.Close()

				log.Println("connected to server ::", connectAddr)

				childCtx, childCancel := context.WithCancel(context.Background())
				go serverLoop(clientConn, serverConn, mainCtx, childCtx, childCancel)
				handleClientConn(clientConn, serverConn, mainCtx, childCtx, childCancel)
			}()
		}
	}
}

func serverLoop(
	clientConn net.Conn,
	serverConn net.Conn,
	mainCtx context.Context,
	childCtx context.Context,
	cancel context.CancelFunc,
) {
	wg.Add(1)
	defer wg.Done()

loop:
	for {
		select {
		case <-mainCtx.Done(): // an interrupt signal was sent
			break loop
		case <-childCtx.Done(): // the proxy system is shutting down
			break loop

		default:
			dataFromServer, err := receive(serverConn, mainCtx, childCtx)
			if err != nil {
				if err != context.Canceled {
					if _, k := err.(*net.OpError); err != io.EOF && !k {
						log.Println("[S->c] error during recv ::", err)
					}
					cancel()
				}
				break loop
			}

			packet, decoded, err := makePacket(dataFromServer[2:], true)
			if err != nil {
				log.Println("[S->c] error creating packet from server data :: ", err)
				cancel()
				break loop
			}

			family_str, _ := packet.Family().String()
			action_str, _ := packet.Action().String()
			log.Printf(
				"[S->c] length (raw): %5d | length (read): %5d | id: %20s | %s\n",
				len(dataFromServer)-2, packet.ByteSize(), fmt.Sprintf("%s_%s", family_str, action_str),
				writeArray(decoded),
			)

			// dumpPacketData(packet, decoded, "server")

			if _, err = clientConn.Write(dataFromServer); err != nil {
				log.Println("[S->c] error during send ::", err)
				cancel()
				break loop
			}
		}
	}

	log.Println("server loop terminated")
}

func handleClientConn(
	clientConn net.Conn,
	serverConn net.Conn,
	mainCtx context.Context,
	childCtx context.Context,
	cancel context.CancelFunc,
) {
	wg.Add(1)
	defer wg.Done()

loop:
	for {
		select {
		case <-mainCtx.Done(): // an interrupt signal was sent
			break loop
		case <-childCtx.Done(): // the proxy system is shutting down
			break loop

		default:
			dataFromClient, err := receive(clientConn, mainCtx, childCtx)
			if err != nil {
				if err != context.Canceled {
					if _, k := err.(*net.OpError); err != io.EOF && !k {
						log.Println("[C->s] error during recv ::", err)
					}
					cancel()
				}
				break loop
			}

			packet, decoded, err := makePacket(dataFromClient[2:], false)
			if err != nil {
				log.Println("[C->s] error creating packet from client data :: ", err)
				cancel()
				break loop
			}

			family_str, _ := packet.Family().String()
			action_str, _ := packet.Action().String()
			log.Printf(
				"[C->s] length (raw): %5d | length (read): %5d | id: %20s | %s\n",
				len(dataFromClient)-2, packet.ByteSize(), fmt.Sprintf("%s_%s", family_str, action_str),
				writeArray(decoded),
			)

			// dumpPacketData(packet, decoded, "client")

			if _, err = serverConn.Write(dataFromClient); err != nil {
				log.Println("[C->s] error during send ::", err)
				cancel()
				break loop
			}
		}
	}

	log.Println("client loop terminated")
}

func receive(conn net.Conn, mainCtx context.Context, childCtx context.Context) (data []byte, err error) {
loop:
	for {
		// time out on reads after 1 second
		// this allows polling for the cancellation signals
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		select {
		case <-mainCtx.Done():
			log.Println("got cancel signal from main")
			err = context.Canceled
			break loop
		case <-childCtx.Done():
			err = context.Canceled
			break loop

		default:
			const LENGTH_LENGTH = 2
			lengthReader := io.LimitReader(conn, LENGTH_LENGTH)
			raw_length := make([]byte, LENGTH_LENGTH)
			if _, err = lengthReader.Read(raw_length); err != nil {
				switch v := err.(type) {
				case *net.OpError:
					if v.Err == os.ErrDeadlineExceeded {
						continue
					}
				}
				break loop
			}
			length := eolib_data.DecodeNumber(raw_length)

			dataReader := io.LimitReader(conn, int64(length))
			message := make([]byte, length)
			if _, err = io.ReadFull(dataReader, message); err != nil {
				switch v := err.(type) {
				case *net.OpError:
					if v.Err == os.ErrDeadlineExceeded {
						continue
					}
				}
				break loop
			}

			data = append(raw_length, message...)

			if len(data) < 4 {
				err = fmt.Errorf("invalid message: not enough info in data header")
			}

			break loop
		}
	}

	return
}

func makePacket(data []byte, is_server bool) (packet eolib_net.Packet, decoded_data []byte, err error) {
	dataStart := 2
	if is_server {
		if server_encryption_multiple != nil {
			decoded_data, _ = eolib_encrypt.SwapMultiples(eolib_encrypt.Deinterleave(eolib_encrypt.FlipMsb(data)), *server_encryption_multiple)
		} else {
			decoded_data = data
		}
	} else {
		if client_encryption_multiple != nil {
			decoded_data, _ = eolib_encrypt.SwapMultiples(eolib_encrypt.Deinterleave(eolib_encrypt.FlipMsb(data)), *client_encryption_multiple)

			nextSequence := sequencer.NextSequence()
			if nextSequence >= eolib_data.CHAR_MAX {
				dataStart = 4
			} else {
				dataStart = 3
			}

			actualSequence := eolib_data.DecodeNumber(decoded_data[2:dataStart])
			if actualSequence != nextSequence {
				err = fmt.Errorf("mismatched sequence: client sent %d, expected %d", actualSequence, nextSequence)
				return
			}

		} else {
			decoded_data = data
		}
	}

	family := eolib_net.PacketFamily(decoded_data[1])
	action := eolib_net.PacketAction(decoded_data[0])
	family_str, _ := family.String()
	action_str, _ := action.String()

	if is_server {
		if packet, err = eolib_server.PacketFromId(family, action); err != nil {
			err = fmt.Errorf("unrecognized packet: %s_%s", family_str, action_str)
			return
		}
	} else {
		if packet, err = eolib_client.PacketFromId(family, action); err != nil {
			err = fmt.Errorf("unrecognized packet: %s_%s", family_str, action_str)
			return
		}
	}

	dataReader := eolib_data.NewEoReader(decoded_data[dataStart:])
	if err = packet.Deserialize(dataReader); err != nil {
		packet = nil
		return
	}

	switch pkt := packet.(type) {
	case *eolib_server.InitInitServerPacket:
		if pkt.ReplyCode != eolib_server.InitReply_Ok {
			replyCodeString, _ := pkt.ReplyCode.String()
			err = fmt.Errorf("invalid reply code: %s", replyCodeString)
			return
		}

		switch replyCodeData := pkt.ReplyCodeData.(type) {
		case *eolib_server.InitInitReplyCodeDataOk:
			client_encryption_multiple = new(int)
			*client_encryption_multiple = replyCodeData.ClientEncryptionMultiple
			server_encryption_multiple = new(int)
			*server_encryption_multiple = replyCodeData.ServerEncryptionMultiple

			sequence = eolib_packet.NewInitSequence(replyCodeData.Seq1, replyCodeData.Seq2)
			sequencer = eolib_packet.NewPacketSequencer(sequence)
			sequencer.NextSequence()
		}
	case *eolib_server.ConnectionPlayerServerPacket:
		sequence = eolib_packet.NewPingSequence(pkt.Seq1, pkt.Seq2)
		sequencer = eolib_packet.NewPacketSequencer(sequence)
	case *eolib_server.AccountReplyServerPacket:
		if pkt.ReplyCode <= 9 {
			break
		}
		switch replyCodeData := pkt.ReplyCodeData.(type) {
		case *eolib_server.AccountReplyReplyCodeDataDefault:
			sequence = eolib_packet.NewAccountReplySequence(replyCodeData.SequenceStart)
			sequencer = eolib_packet.NewPacketSequencer(sequence)
		}
	}

	return
}

func writeArray(data []byte) string {
	out := strings.Builder{}

	for i := range data {
		if i > 0 {
			out.WriteString(" ")
		}

		out.WriteString(fmt.Sprintf("0x%02X", data[i]))
	}

	return out.String()
}