package main;

import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Main {
    public static void main(String[] args) {
        try {
            PcapNetworkInterface networkInterface = Pcaps.findAllDevs().get(0);
            ArpRequest.send(networkInterface,
                    networkInterface.getAddresses().get(0).getAddress(),
                    MacAddress.getByAddress(networkInterface.getLinkLayerAddresses().get(0).getAddress()),
                    InetAddress.getByName("192.168.1.1")
            );
        } catch (PcapNativeException | UnknownHostException e) {
            e.printStackTrace();
        }
    }
}
