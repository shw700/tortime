package main

import "net"
import "fmt"
import "os"
import "encoding/binary"
import "time"
import "syscall"
import "unsafe"


const TLS_SERVER = "172.217.0.36:443"
// Maximum clock drift, in seconds
const MAXDRIFT = 60
// Time interval for forcing recalibration, in seconds
const FORCE_RECALIBRATION = (60 * 60 * 1)
// Clock polling interval, in seconds
const POLL_INTERVAL = 5


func setSystemTimeLinux(time_utc uint32) (int, error) {
	const SYSCALL_NO_CLOCK_SETTIME = 227
	const CLOCK_REALTIME = 0

	// timespec is time_t tv_sec; long tv_nsec; (8 bytes + 8 bytes)
	// Create struct timespec
	timespec_bytes := []byte{ 0xde, 0xad, 0xbe, 0xef, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }
	binary.LittleEndian.PutUint64(timespec_bytes, uint64(time_utc))
	tsptr := unsafe.Pointer(&(timespec_bytes[0]))
	r1, _, err := syscall.Syscall(SYSCALL_NO_CLOCK_SETTIME, CLOCK_REALTIME, uintptr(tsptr), 0)

	return int(r1), err
}

func main() {

	clientbytes := []byte{	0x16,				// handshake record (CLIENT_KEY_EXCHANGE)
				0x03, 0x01,			// TLS version (1.0 / SSL 3.1)
				0x00, 0x5f,			// Total size of data in bytes, excluding header (record length)
				0x01,				// ClientHello message type
				0x00, 0x00, 0x5b,		// 3 byte message length
				0x03, 0x01,			// TLS version bytes again
				0x4a, 0x2f, 0x07, 0xca,		// UTC time
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,	// 28 random bytes
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
				0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
				0x00,				// Null session ID
				0x00, 0x2e,			// Cipher suite length
				0x00, 0x39, 0x00, 0x38, 0x00, 0x35, 0x00,	// cipher suite
				0x16, 0x00, 0x13, 0x00, 0x0a, 0x00, 0x33,
				0x00, 0x32, 0x00, 0x2f, 0x00, 0x9a, 0x00,
				0x99, 0x00, 0x96, 0x00, 0x05, 0x00, 0x04,
				0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00,
				0x14, 0x00, 0x11, 0x00, 0x08, 0x00, 0x06,
				0x00, 0x03, 0x00, 0xff,	
				0x01,				// Compression methods length
				0x00,				// Compression method (null)
				0x00, 0x04,			// Extensions length
				0x00, 0x23,			// SessionTicket TLS extension
				0x00, 0x00 }			// Extension data length

	if os.Getuid ()!= 0 {
		fmt.Println("Warning: program is not running as root... setting clock will probably fail.")
	}

	timeloop := 1
	curtime := time.Now().Unix()
	lasttime := curtime
	elapsed := int64(0)

	for timeloop > 0 {

//		fmt.Printf("Sleeping for %d seconds...\n", POLL_INTERVAL)
		time.Sleep(POLL_INTERVAL*1000*1000*1000)

		curtime := time.Now().Unix()
		diff := curtime - lasttime

		if (lasttime > curtime) {
			diff = lasttime - curtime
		}

		elapsed += diff

		tmplasttime := lasttime
		lasttime = curtime

		if (elapsed >= FORCE_RECALIBRATION) {
			fmt.Println("Reached maximum time elapsed... forcing recalibration")
			elapsed = 0
		} else if (diff >= MAXDRIFT) {
			fmt.Printf("Exceeded maximum clock drift (%d vs %d seconds)... forcing time update\n", diff, MAXDRIFT)
		} else {
//			fmt.Printf("%d seconds have elapsed, last diff was %d...\n", elapsed, diff)
//			fmt.Printf("current vs last = %u vs %u\n", curtime, tmplasttime)
			continue
		}


		// fmt.Printf("data size is %d\n", len(clientbytes))

		fmt.Printf("Attempting to connect to %s ...\n", TLS_SERVER)
		conn, err := net.Dial("tcp", TLS_SERVER)

		if err != nil {
			fmt.Println("Could not establish connection to SSL server: ", err)
			os.Exit(-1)
		}

		fmt.Println("Made connection to remote TLS server...")

		conn.Write(clientbytes)

		inbuf := make([]byte, 4096)

		nread, err := conn.Read(inbuf)

		if err != nil {
			fmt.Println("Error reading response from server: ", err)
			os.Exit(-1)
		}

		fmt.Printf("got back %d bytes\n", nread)

		if nread < 16 {
			fmt.Println("There was a problem reading the response. Much shorter than expected.")
			os.Exit(-1)
		}

		utcbytes := inbuf[11:15]
		utcnum := binary.BigEndian.Uint32(utcbytes)

		fmt.Println("UTC bytes: ", utcbytes)
		fmt.Printf("UTC num is %d\n", utcnum)

		fmt.Printf("Google server UTC time is: %s\n", time.Unix(int64(utcnum), 0))

		_, err = setSystemTimeLinux(utcnum)

		if err != nil {
			fmt.Println("Attempt to set system clock failed: ", err)
		}

	}

}
