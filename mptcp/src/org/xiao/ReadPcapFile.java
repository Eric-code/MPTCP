package org.xiao;
import java.io.*;
import java.net.Inet4Address;
import java.text.DecimalFormat;
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
    private static final int LABEL = 2;
    private static final String APP = "google";
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "packets_default.pcap");
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
        String filename = "Comnet-14_all"+APP+".txt";
        String lineTxt = null;
        PrintWriter writer = null;
        DecimalFormat df = new DecimalFormat("###.0");

        Boolean findPacket = false;
        Boolean stop = false;
        String []s = {null,null,null,null,null,null,null,null,null,null,null};
        PcapHandle handle;
        int srcPort = 0;
        int dstPort = 0;
        int windowSize = 0;
        int dir = 0;
        int payload = 0;
        try {
            handle = Pcaps.openOffline(PCAP_FILE);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
        try {
            File file = new File(filePath);
            File writefile = new File(filename);
            try {
                writer = new PrintWriter(new FileOutputStream(writefile));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
                double startTime = 0;
                double endTime = 0;
                double timestamp = 0;
                double lasttimestamp = 0;
                double time = 0;
                while (((lineTxt = br.readLine()) != null)&&(!stop)) {
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
                        while (findPacket&&(!stop)){
                            try {
                                Packet packet = handle.getNextPacketEx();
                                byte []raw = packet.getRawData();
                                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                                IpNumber protocol = ipV4Packet.getHeader().getProtocol();   // 包协议名
                                int len = ipV4Packet.getHeader().getTotalLengthAsInt() + 14;  // 包字节数
//                                System.out.println(len);
//                                byte []a = ipV4Packet.getHeader().getSrcAddr().getAddress();
//                                byte []b = ipV4Packet.getHeader().getDstAddr().getAddress();
                                String srcAddress = ipV4Packet.getHeader().getSrcAddr().toString();
                                String dstAddress = ipV4Packet.getHeader().getDstAddr().toString();
                                timestamp = (double)handle.getTimestampInts()*1000000 + handle.getTimestampMicros();
                                time = timestamp - lasttimestamp;
                                if ((timestamp>=startTime)&&(timestamp<=endTime)){
                                    if (((srcAddress.equals("/"+s[3]))&&(dstAddress.equals("/"+s[4])))||((srcAddress.equals("/"+s[4]))&&(dstAddress.equals("/"+s[3])))){
                                        System.out.println(timestamp+"    "+count);
                                        count++;
                                        for (int j = 0;j<54;j++){
                                            writer.print(df.format(raw[j]));
                                            writer.print(',');
                                        }
//                                        for (int j = 0;j<4;j++){
//                                            writer.print(df.format(a[j]));
//                                            writer.print(',');
//                                        }
//                                        for (int j = 0;j<4;j++){
//                                            writer.print(df.format(b[j]));
//                                            writer.print(',');
//                                        }
                                        if (srcAddress.equals("/"+s[3])){
                                            dir = 1;//上行流
                                        }else {
                                            dir = 0;//下行流
                                        }
//                                        if (protocol.toString().equals("6(TCP)")){
//                                            TcpPacket tcpPacket = packet.get(TcpPacket.class);
//                                            srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
//                                            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
//                                            windowSize = tcpPacket.getHeader().getWindowAsInt();
//                                            try {
//                                                payload = tcpPacket.getPayload().length();
//                                            }catch (NullPointerException e){
//                                                payload = 0;
//                                            }
//                                        }else if (protocol.toString().equals("17(UDP)")){
//                                            UdpPacket udpPacket = packet.get(UdpPacket.class);
//                                            srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
//                                            dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
//                                            windowSize = 0;
//                                            try {
//                                                payload = udpPacket.getPayload().length();
//                                            }catch (NullPointerException e){
//                                                payload = 0;
//                                            }
//                                        }
//                                        writer.print(df.format(srcPort));
//                                        writer.print(',');
//                                        writer.print(df.format(dstPort));
//                                        writer.print(',');
//                                        writer.print(df.format(windowSize));
//                                        writer.print(',');
                                        writer.print(df.format(dir));
                                        writer.print(',');
//                                        writer.print(df.format(payload));
//                                        writer.print(',');
                                        if (count == 1){
                                            writer.print(df.format(0));
                                            writer.print(',');
                                        }else {
                                            writer.print(df.format(time));
                                            writer.print(',');
                                        }
                                        writer.print(df.format(len));
                                        writer.print(',');
                                        writer.println(LABEL);
                                        lasttimestamp = timestamp;
                                        if (count == 120000){
                                            stop = true;
                                            break;
                                        }
                                    }
                                }else if (timestamp>endTime){
                                    findPacket = false;
                                }
                            } catch (TimeoutException e) {
                            } catch (EOFException e) {
                                System.out.println("EOF");
                            }
                        }
                        handle.close();
                    }
                }
                br.close();
            } else {
                System.out.println("文件不存在!");
            }
        } catch (Exception e) {
            System.out.println("文件读取错误!");
            e.printStackTrace();
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
