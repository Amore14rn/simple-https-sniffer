package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"
	"log"
	"net"
	"os"
)

type Transfer struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  layers.TCPPort
	DstPort  layers.TCPPort
	OptCount int
}

type LayersData struct {
	eth           layers.Ethernet
	ip4           layers.IPv4
	ip6           layers.IPv6
	tcp           layers.TCP
	tls           layers.TLS
	payload       gopacket.Payload
	parser        *gopacket.DecodingLayerParser
	decodedLayers []gopacket.LayerType
}

type Device struct {
	Handle      *pcap.Handle
	Addresses   []pcap.InterfaceAddress
	Name        string
	Description string
	Filter      string
}

func main() {
	app := cli.NewApp()

	app.Name = "Simple https sniffer"
	app.Usage = "An example how to sniff tcp/ip"
	app.Authors = append(app.Authors, &cli.Author{Name: "Alexander Koval", Email: "toalexkoval@gmail.com"})
	app.Version = "0.0.1"

	app.Commands = []*cli.Command{
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "Get list of system devices",
			Action:  listCommand,
		},
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run the sniffer",
			Action:  runCommand,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

/* Layers Data */
func NewLayersData() *LayersData {
	ld := new(LayersData)
	ld.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ld.eth, &ld.ip4, &ld.ip6, &ld.tcp, &ld.tls, &ld.payload)
	ld.decodedLayers = make([]gopacket.LayerType, 0, 10)

	return ld
}

/* Transfer */
func NewTransfer() *Transfer {
	return &Transfer{}
}

func (t *Transfer) DecodeFromPacket(data []byte, ld *LayersData) {
	_ = ld.parser.DecodeLayers(data, &ld.decodedLayers)

	for _, typ := range ld.decodedLayers {
		switch typ {
		case layers.LayerTypeIPv4:
			t.SrcIP = ld.ip4.SrcIP
			t.DstIP = ld.ip4.DstIP
		case layers.LayerTypeIPv6:
			t.SrcIP = ld.ip6.SrcIP
			t.DstIP = ld.ip6.DstIP
		case layers.LayerTypeTCP:
			t.SrcPort = ld.tcp.SrcPort
			t.DstPort = ld.tcp.DstPort
			t.OptCount = len(ld.tcp.Options)
			//case layers.LayerTypeTLS:
			//spew.Dump(tls)
		}
	}
}

func (t *Transfer) GetOutput() string {
	return fmt.Sprintf("%s,%d,%s,%d,%d",
		t.SrcIP,
		t.SrcPort,
		t.DstIP,
		t.DstPort,
		t.OptCount)
}

/* Device */
func NewDevice(name string) *Device {
	return &Device{Name: name}
}

func (d *Device) SetFilter(filter string) error {
	d.Filter = filter
	if err := d.Handle.SetBPFFilter(d.Filter); err != nil {
		return err
	}

	return nil
}

func (d *Device) Open() error {
	var err error
	d.Handle, err = pcap.OpenLive(d.Name, 1600, false, pcap.BlockForever)
	if err != nil {
		return err
	}

	return nil
}

func (d *Device) Sniff() {
	ld := NewLayersData()

	for {
		data, _, err := d.Handle.ReadPacketData()
		if err != nil {
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		transfer := NewTransfer()
		transfer.DecodeFromPacket(data, ld)
		fmt.Println(transfer.GetOutput())
	}
}

/* Cli Commands */
func listCommand(c *cli.Context) error {
	devices, err := getDevices()
	if err != nil {
		return err
	}

	if len(devices) == 0 {
		fmt.Println("No devices found:")
		return nil
	}

	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ")

		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}

	return nil
}

func runCommand(c *cli.Context) error {
	devName := c.Args().Get(0)
	if len(devName) == 0 {
		return errors.New("Device name is required. ")
	}

	device := NewDevice(devName)
	if err := device.Open(); err != nil {
		log.Fatal(err)
	}
	defer device.Handle.Close()

	//filter := "(tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)"
	filter := "(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)"
	if err := device.SetFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\t Interface: %s \n\t Filter: %s \n", device.Name, device.Filter)
	device.Sniff()

	return nil
}

/* Functions */
func getDevices() ([]*Device, error) {
	var list []*Device

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return list, err
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 { // only ethernet
			cDev := NewDevice(device.Name)
			cDev.Description = device.Description
			cDev.Addresses = device.Addresses
			list = append(list, cDev)
		}
	}

	return list, nil
}
