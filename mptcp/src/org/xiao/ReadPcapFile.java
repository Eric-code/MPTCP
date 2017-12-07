package org.xiao;
import java.io.*;
import java.net.Inet4Address;
import java.util.Arrays;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

public class ReadPcapFile {
    private static final int COUNT = 100;
    private static final String APP = "facebook";
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/dataset/CBA_dataset/Comnet-14-Traces/packets_default.pcap");
    private ReadPcapFile() {}

    public static void readTxt(String filePath){
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null};
        try {
            File file = new File(filePath);
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
//                while ((lineTxt = br.readLine()) != null) {
                for (int i =0;i<10;i++){
//                    System.out.println(lineTxt);
                    lineTxt = br.readLine();
                    count++;
                    System.out.println(count);
                    s = lineTxt.split("#");
                    for (int j =0;j<11;j++){
                        System.out.println(s[j]);
                    }
                }
                br.close();
            } else {
                System.out.println("文件不存在!");
            }
        } catch (Exception e) {
            System.out.println("文件读取错误!");
        }
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filePath = "packets_default.info";
        String lineTxt = null;
        Boolean findPacket = false;
        String []s = {null,null,null,null,null,null,null,null,null,null,null};
        PcapHandle handle;
        TcpPort srcTcpPort,dstTcpPort;
        UdpPort srcUdpPort,dstUdpPort;
        try {
            handle = Pcaps.openOffline(PCAP_FILE);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
        try {
            File file = new File(filePath);
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
                double startTime = 0;
                double endTime = 0;
                while ((lineTxt = br.readLine()) != null) {
//                for (int i =0;i<10;i++){
                    if (lineTxt.contains(APP)){
                        s = lineTxt.split("#");
                        startTime=Double.valueOf(s[1]);
                        endTime=Double.valueOf(s[2]);
                        findPacket = true;
                        try {
                            handle = Pcaps.openOffline(PCAP_FILE);
                        } catch (PcapNativeException e) {
                            handle = Pcaps.openOffline(PCAP_FILE);
                        }
                        while (findPacket){
                            try {
                                Packet packet = handle.getNextPacketEx();
                                count++;
                                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                                IpNumber protocol = ipV4Packet.getHeader().getProtocol();
                                String srcAddress = ipV4Packet.getHeader().getSrcAddr().toString();
                                String dstAddress = ipV4Packet.getHeader().getDstAddr().toString();
                                double timestamp = (double)handle.getTimestampInts()*1000000 + handle.getTimestampMicros();
                                if ((timestamp>=startTime)&&(timestamp<=endTime)){
                                    if (((srcAddress.equals("/"+s[3]))&&(dstAddress.equals("/"+s[4])))||((srcAddress.equals("/"+s[4]))&&(dstAddress.equals("/"+s[3])))){
                                        System.out.println(timestamp+"    "+count);
                                    }
                                }else if (timestamp>endTime){
                                    findPacket = false;
                                }
                                if (protocol.toString().equals("6(TCP)")){
                                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                                    srcTcpPort = tcpPacket.getHeader().getSrcPort();
                                    dstTcpPort = tcpPacket.getHeader().getDstPort();
                                }else if (protocol.toString().equals("17(UDP)")){
                                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                                    srcUdpPort = udpPacket.getHeader().getSrcPort();
                                    dstUdpPort = udpPacket.getHeader().getDstPort();
                                }
                            } catch (TimeoutException e) {
                            } catch (EOFException e) {
                                System.out.println("EOF");
                            }catch (NullPointerException e){
                            }
                        }

                    }

//                    for (int j =0;j<11;j++){
//                        System.out.println(s[j]);
//                    }
                }
                handle.close();
                br.close();
            } else {
                System.out.println("文件不存在!");
            }
        } catch (Exception e) {
            System.out.println("文件读取错误!");
        }
//        String []tuple = {null,null,null,null,null};
//        String []newtuple = {null,null,null,null,null};
//        PcapHandle handle;
//        TcpPort srcTcpPort,dstTcpPort;
//        UdpPort srcUdpPort,dstUdpPort;
//        Inet4Address srcAddress,dstAddress;
//        try {
//            handle = Pcaps.openOffline(PCAP_FILE);
//        } catch (PcapNativeException e) {
//            handle = Pcaps.openOffline(PCAP_FILE);
//        }
//
//        try {
//            Packet packet = handle.getNextPacketEx();
//            double timestamp = (double)handle.getTimestampInts()*1000000 + handle.getTimestampMicros();
//            System.out.println(timestamp);
//            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
//            IpNumber protocol = ipV4Packet.getHeader().getProtocol();
//            tuple[0] = protocol.toString();
//            srcAddress = ipV4Packet.getHeader().getSrcAddr();
//            dstAddress = ipV4Packet.getHeader().getDstAddr();
//            tuple[1] = srcAddress.toString();
//            tuple[2] = dstAddress.toString();
//            if (protocol.toString().equals("6(TCP)")){
//                TcpPacket tcpPacket = packet.get(TcpPacket.class);
//                srcTcpPort = tcpPacket.getHeader().getSrcPort();
//                dstTcpPort = tcpPacket.getHeader().getDstPort();
//                tuple[3] = srcTcpPort.toString();
//                tuple[4] = dstTcpPort.toString();
//            }else if (protocol.toString().equals("17(UDP)")){
//                UdpPacket udpPacket = packet.get(UdpPacket.class);
//                srcUdpPort = udpPacket.getHeader().getSrcPort();
//                dstUdpPort = udpPacket.getHeader().getDstPort();
//                tuple[3] = srcUdpPort.toString();
//                tuple[4] = dstUdpPort.toString();
//            }
//        } catch (TimeoutException e) {
//        } catch (EOFException e) {
//            System.out.println("EOF");
//        }catch (NullPointerException e){
//        }
//
//        double i = 0;
//        int count = 1;
//        boolean rst = false;
//        boolean ask = false;
////        while (true){
//        for (int m = 2; m < COUNT;m ++){
//            try {
//                Packet packet = handle.getNextPacketEx();
//                double timestamp = (double)handle.getTimestampInts()*1000000 + handle.getTimestampMicros();
//                System.out.println(m+"+"+timestamp);
//                count++;
//                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
//                IpNumber protocol = ipV4Packet.getHeader().getProtocol();
//                newtuple[0] = protocol.toString();
//                srcAddress = ipV4Packet.getHeader().getSrcAddr();
//                dstAddress = ipV4Packet.getHeader().getDstAddr();
//                newtuple[1] = srcAddress.toString();
//                newtuple[2] = dstAddress.toString();
//                if (protocol.toString().equals("6(TCP)")){
//                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
//                    srcTcpPort = tcpPacket.getHeader().getSrcPort();
//                    dstTcpPort = tcpPacket.getHeader().getDstPort();
////                    rst =tcpPacket.getHeader().getRst();
////                    ask = tcpPacket.getHeader().getAck();
//                    newtuple[3] = srcTcpPort.toString();
//                    newtuple[4] = dstTcpPort.toString();
////                    if (rst&&ask){
////                        i++;
////                        System.out.print(i);
////                        System.out.println("a"+count);
////                    }
//                }else if (protocol.toString().equals("17(UDP)")){
//                    UdpPacket udpPacket = packet.get(UdpPacket.class);
//                    srcUdpPort = udpPacket.getHeader().getSrcPort();
//                    dstUdpPort = udpPacket.getHeader().getDstPort();
//                    newtuple[3] = srcUdpPort.toString();
//                    newtuple[4] = dstUdpPort.toString();
//                }
////                System.out.println();
//            } catch (TimeoutException e) {
//            } catch (EOFException e) {
//                System.out.println("EOF");
//                break;
//            }catch (NullPointerException e){
//            }
//
////            boolean up = ((newtuple[0].equals(tuple[0]))&&(newtuple[1].equals(tuple[1]))&&(newtuple[2].equals(tuple[2]))&&(newtuple[3].equals(tuple[3]))&&(newtuple[4].equals(tuple[4])));
////            boolean down = ((newtuple[0].equals(tuple[0]))&&(newtuple[1].equals(tuple[2]))&&(newtuple[2].equals(tuple[1]))&&(newtuple[3].equals(tuple[4]))&&(newtuple[4].equals(tuple[3])));
////            if (up || down){
////            }else{
////                for (int j = 0; j<5; j++){
////                    tuple[j] = newtuple[j];
////                }
////                i++;
////                System.out.println(i);
////                System.out.println("a"+count);
////            }
//
//        }
//        handle.close();
    }

}
