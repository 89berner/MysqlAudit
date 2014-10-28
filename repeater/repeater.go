	package main
	
	import (
		"time"
		"os"
		"net"
		"fmt"
		//"github.com/akrennmair/gopcap"
		"log"
		"io"
		"pcap"
		//"math/rand"
		"strings"
		//"regexp"
	)
	
	var start int64 = UnixNow()
	var packetcount int32 = 0
	var verbose bool = false
	var dirty bool = false
	var format []interface{}
	var port uint16
	var connections map[string]string = make(map[string]string)
	var dbusers map[string]string = make(map[string]string)
	var localip string
	
	var f *os.File
	
	func UnixNow() int64 {
		return time.Now().Unix()
	}
	
	// recibe una conexion que le manda paquetes y los repite a la interfaz
	func main() {
		fmt.Print("Comienza Repeater\n")	 
		fmt.Printf("Poner como parametro el puerto a escuchar lo que hay que repetir\n")
	
		srcport := os.Args[1] // port
	
		fmt.Printf("Inicializo escuchando en el puerto %s\n",srcport)
	
		ln, err := net.Listen("tcp", fmt.Sprintf(":%s",srcport))
		if err != nil {
			// handle error
		}
		defer ln.Close()
	
		for {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				continue
			}
			go handleConnection(conn,f)
		}
	}
	
	func handleConnection(c net.Conn, f *os.File) {
	
		defer func() {
	             if r := recover(); r != nil {
	                  fmt.Println("Recovered in handleConnection", r)
	             }
		}()
	
	    msgchan := make(chan []byte) //1024*1024
	    
	    var contador = 0;

	    var size uint32
	    var rest uint32
	    var first = 1
	
	    for {
	    	buf2 := make([]byte, 2)
		xn, xerr := io.ReadFull(c, buf2)
			        
		if xerr != nil || xn == 0 {
			if (first == 0) {
			  log.Printf("Error con buf2 con xn %d y err: %s ,.cierro..",xn,xerr)
			}
			close (msgchan)
			c.Close()
			return
		}
		
		if (first == 1) {
			first = 0
			log.Printf("Nueva conexion de %v.", c.RemoteAddr())
			go printMessages(msgchan)
		}
		
		if (xn != 2) {
			fmt.Printf("En primera lectura lei %d\n",xn)
		}
			        
		rsize := buf2[0]
		size = uint32(rsize)
		rrest := buf2[1]
		rest = uint32(rrest)
		
		if size == 0 {
			continue
		}
			        
		//log.Printf("Me dio size: %d y rest %d ",size,rest)

	        xtam := size*100-rest
	        
		buf := make([]byte, size*100)
		var n int
	        n, err := io.ReadFull(c, buf)
		        if err != nil || n == 0 {
				close (msgchan)
		        	log.Printf("Error en buf...")
				c.Close()
		        	return
		        }

	        tam := n
	
	        contador = contador + 1
	        if (contador % 100 == 0 ) {
	        	//fmt.Printf("handleConnection: Me dice que el tamaño total es %d con un size de %d y un rest de %d y el mensaje es %v\n", xtam, size,rest, buf2)
	        	fmt.Printf("handleConnection: Cantidad %d y xtam %d\n", contador,tam)
	        }
	        
	        msgchan <- buf[0:xtam]
	    }
	}
	
	func printMessages(msgchan <-chan []byte) {
	
		defer func() {
	             if r := recover(); r != nil {
	                  fmt.Println("Recovered in printMessages", r)
	             }
		}()
		
		var contador = 0;
	
		var eth = "eth0"
		
		if handle, err := pcap.OpenLive(eth, 10240, false, 0); err != nil {
		  //panic(err)
		  fmt.Printf("Error en pcap!!!!")
		} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
		  //panic(err)
		  fmt.Printf("Error en pcap!!!!")
		} else {
		       //fmt.Println("Esperando para mandar de: %d", contador)
		     for msg := range msgchan {
		        contador = contador + 1
		        
		        if (contador % 100 == 0) {
		        	fmt.Printf("printMessages: Cantidad: %d y tamaño %d\n", contador, len(msg))
		        }
	
		        handle.WritePacketData(msg)
		    }
		  fmt.Printf("Go routine terminada!!!!")
		}
	}
	
