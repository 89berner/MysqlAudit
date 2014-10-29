To install in ubuntu:

cd /usr/local

wget https://storage.googleapis.com/golang/go1.3.3.linux-amd64.tar.gz 

tar -xvzf go1.3.3.linux-amd64.tar.gz 

export PATH=$PATH:/usr/local/go/bin

export GOPATH=/usr/local/go/bin

apt-get install git

apt-get install gcc

apt-get install libpcap-dev

go get code.google.com/p/gopacket

go build agent.go

You can run it with:

./agent eth0 3306 11.22.33.44 9200 1000 5000 5

Where:

etho -> interface
3306 -> port to listen to
11.22.33.44 -> Destination ip
9200 -> Destination port
1000 -> Time in miliseconds
5000 -> Packet size
5 -> 5 MB of buffer

