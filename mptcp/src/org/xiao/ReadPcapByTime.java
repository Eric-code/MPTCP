package org.xiao;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

public class ReadPcapByTime {
    private static final int COUNT = 100;
    private double start_time = 1361810326840284.0;
    private double end_time = 1361810329708950.0;
    private static final String FILE="amazon_";
    private static int ORDER=1;//起始文件标号
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/dataset/CBA_dataset/Comnet-14 Traces/packets_default.pcap");
    boolean flag = true;
    private ReadPcapByTime() {}

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }

        for (int i = 0; i < COUNT; i++) {
            try {
                Packet packet = handle.getNextPacketEx();
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                System.out.print(((double) handle.getTimestampInts() * 1000000 + handle.getTimestampMicros()) + ",");
                System.out.print(ipV4Packet.getHeader().getSrcAddr() + ",");
                System.out.print(ipV4Packet.getHeader().getDstAddr() + ",");
                System.out.print(tcpPacket.getHeader().getSrcPort() + ",");
                System.out.print(tcpPacket.getHeader().getDstPort());
                System.out.println();
            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }catch (NullPointerException e){
                System.out.println("lenth = 0");
            }
        }
        handle.close();
    }


}
