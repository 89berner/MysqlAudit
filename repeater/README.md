Install repeater:

cd /usr/local

wget https://storage.googleapis.com/golang/go1.3.3.linux-amd64.tar.gz 

tar -xvzf go1.3.3.linux-amd64.tar.gz 

export PATH=$PATH:/usr/local/go/bin

export GOPATH=/usr/local/go/bin

apt-get install git

apt-get install gcc

apt-get install libpcap-dev

go get code.google.com/p/gopacket

run with:

./repeater 9200

where 9200 is the port to listen for the agent
