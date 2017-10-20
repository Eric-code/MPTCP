package org.xiao;

import java.io.EOFException;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
//import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

@SuppressWarnings("javadoc")
public class ReadPacketFile {
    private static final int COUNT = 10-1;//796811,1085027,85366,88710,81884,136091,226401,159026
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "E:/wangyan/traffic-classfication/data/douyu_up.pcap");
    private ReadPacketFile() {}
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        double sum = 0;
        double len = 0;
        int []pck_cnt = new int[1600];
        Arrays.fill(pck_cnt,0);  //用value值填充全部的arr元素。
        double result = 0;
        double firsttample=0;
        double lasttample=0;
        int subcount = 0;
        try {
            handle = Pcaps.openOffline(PCAP_FILE);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
        Inet4Address inet4AddressPre=handle.getNextPacket().get(IpV4Packet.class).getHeader().getSrcAddr();
        for (int i = 0; i < COUNT; i++) {
            try {
                Packet packet = handle.getNextPacketEx();
                IpV4Packet ipV4Packet= packet.get(IpV4Packet.class);
                Inet4Address inet4Address = ipV4Packet.getHeader().getSrcAddr();
                if (i == 0){
                    firsttample=(double)handle.getTimestampInts()*1000000+handle.getTimestampMicros();
                    subcount++;
                }
                if (i == COUNT-1){
                    lasttample=(double)handle.getTimestampInts()*1000000+handle.getTimestampMicros();
                }
//                UdpPacket udpPacket = packet.get(UdpPacket.class);
                if (!inet4Address.equals(inet4AddressPre)){
                    inet4AddressPre=inet4Address;
                    subcount++;
                }
                len = ipV4Packet.getHeader().getTotalLengthAsInt()+14+16;
                pck_cnt[(int)len]=pck_cnt[(int)len]+1;
                sum = sum + len;
//                System.out.println(packet);
//                System.out.println(ipV4Packet.getHeader().getTotalLengthAsInt());
//                System.out.println(udpPacket.getHeader().getDstPort());
                System.out.println(i);
//                System.out.println(handle.getTimestampMicros());
            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }
        for (int j =0;j<1600;j++){
            if (pck_cnt[j]!=0){
                result = result - ((double) pck_cnt[j]/COUNT) * (Math.log((double) pck_cnt[j]/COUNT)/Math.log((double)2));
            }
        }
//        System.out.println(4.9072606E7/4.0565568E7);//4.9072606E7
        System.out.println("熵："+result);
        System.out.println("下行流分段数："+Math.log(subcount));
        System.out.println(sum);//7.8679316E7
        System.out.println("平均时间间隔："+(lasttample-firsttample)/226401+"微秒");//4.8186777E7,1.306811573E9,7.0507805E7,1.337192329E9,8.1663159E7,1.352382707E9
        handle.close();
    }
}
