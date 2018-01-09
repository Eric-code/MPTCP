package org.xiao;
import java.io.EOFException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class readpcap {
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "packets_default.pcap");
    private readpcap() {}

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
        boolean flag = true;
        int i = 0;
        while (flag){
            try {
                i++ ;
                Packet packet = handle.getNextPacketEx();
                double timestamp = (double)handle.getTimestampInts()*1000000 + handle.getTimestampMicros();
                System.out.println(i);
                if (timestamp == 1.382533123222543E15){
                    flag = false;
                }
            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }

        handle.close();
    }

}
