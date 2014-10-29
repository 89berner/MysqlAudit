

package main

import (
	"time"
	//"encoding/binary"
	"os"
	"net"
	"fmt"
        "code.google.com/p/gopacket"
        "code.google.com/p/gopacket/pcap"
	"log"
	"math/rand"
	//"strings"
	//"regexp"
       "strconv"
)

var start int64 = UnixNow()
var packetcount int32 = 0
var verbose bool = false
var dirty bool = false
var format []interface{}
var port uint16
var connections map[string]string = make(map[string]string)
var dbusers map[string]string = make(map[string]string)


func UnixNow() int64 {
	return time.Now().Unix()
}

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("Opciones son: 1) Interfaz 2) Puerto (puede ser * ) 3) IP DESTINO 4) PUERTO DESTINO 5)Timeout 6) Snaplen 7) Buffersize\n")
	
	eth := os.Args[1] // interface
	port := os.Args[2] // port
	destination := os.Args[3] // destination
	destinationport := os.Args[4] // destination

	timeout, err := strconv.Atoi(os.Args[5]); 
	if err != nil { 
	  // Invalid string 
	} 

	snaplen, err := strconv.Atoi(os.Args[6]); 
	if err != nil { 
	  // Invalid string 
	} 	
	
	buffer, err := strconv.Atoi(os.Args[7]); 
	if err != nil { 
	  // Invalid string 
	} 	

	fmt.Printf("Inicializo escuchando en la interfaz %s bajo el puerto %s y mando a %s:%s\n",eth,port,destination,destinationport)

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing Agent sniffing on %s...",port)
	
	inactive, err := pcap.NewInactiveHandle(eth)
	if err != nil {
	  log.Fatal(err)
	}
	defer inactive.CleanUp()
	
	if err = inactive.SetTimeout(time.Duration(timeout) * time.Second); err != nil {
	  log.Fatal(err)
	}
	
	if err = inactive.SetSnapLen(snaplen); err != nil {
	  log.Fatal(err)
	}
	
	if err = inactive.SetBufferSize(buffer * 1024 * 1024); err != nil {
	  log.Fatal(err)
	}
	
	iface, err := inactive.Activate()  // after this, inactive is no longer valid
	if err != nil {
	  log.Fatal(err)
	}
	defer iface.Close()
	
	if port != "*" {
		err = iface.SetBPFFilter(fmt.Sprintf("tcp port %s",port))
		if err != nil {
			log.Fatalf("Failed to set port filter: %s", err.Error())
		}
	}

	log.Print("Ahora voy paquete por paquete")	 
	
	packetchan := make(chan gopacket.Packet)
	go handlepackets(packetchan,destination,destinationport)
	
	var contador = 0

	packetSource := gopacket.NewPacketSource(iface, iface.LinkType())
	for pkt := range packetSource.Packets() {

			tipo := make([]byte, 1)
			tipo[0] = 2
			pkt = pkt

			packetchan <-  pkt
			
			contador = contador + 1
			
			//fmt.Println("Cantidad: %d", contador)
			
			if (contador % 100 == 0) {
				stats, err := iface.Stats()
				err = err
				fmt.Printf("Dropped: %d y Cantidad %d\n", stats.PacketsDropped,contador)
			}

	}
	
	
	
}


func handlepackets(msgchan <-chan gopacket.Packet, destination string, destinationport string ) {
	
	fmt.Println("En handlepackets")
	
	defer func() {
             if r := recover(); r != nil {
                  fmt.Println("Recovered in printMessages", r)
             }
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s",destination,destinationport))
	if err != nil {
		log.Fatalf("No me pude conectar a un parser: %s", err.Error())
	}
	
	conn = conn
	
	var contador = 0;

	log.Printf("Iniciando handlepackets...")
	
	
	for msg := range msgchan {

			if len(msg.Data()) > 0 {
				var i int = len(msg.Data())
				sizetosend := (i / 100) + 1
								
				var h, l uint8 = uint8(sizetosend>>8), uint8(sizetosend&0xff)
				h = h
				sl := make([]byte, 1)
				sl[0] = l

				missingtoadd := (sizetosend * 100) - len(msg.Data())

				var xh, xl uint8 = uint8(missingtoadd>>8), uint8(missingtoadd&0xff)
				xh = xh
				xsl := make([]byte, 1)
				xsl[0] = xl

				rsend := append(sl,xsl...)
				send := append(rsend,msg.Data()...)

				//totalsize := len(send) + missingtoadd
				
				empty := make([]byte, missingtoadd)

				xsend := append(send,empty...)
				fmt.Println("Mande un paquete..")

				if _, err := conn.Write([]byte(xsend)); err != nil {
					log.Fatalf("No me pude conectar a un parser: %s", err.Error())
				}
		
			contador = contador + 1
			if (contador % 100 == 0) {
				fmt.Printf("%s Handle Cantidad: %d y tamaño %d \n",time.Now().Format("Mon Jan 2 15:04:05") , contador, len(msg.Data()),  )
			}
		}
	} 
}
