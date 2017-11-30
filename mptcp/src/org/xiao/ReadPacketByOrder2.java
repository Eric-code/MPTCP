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
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

public class ReadPacketByOrder2 {
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String FILE="ssl_";
    private static int ORDER=1;//起始文件标号
    private static int COUNT=100;//循环检测的pcap文件数量
    private static String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/SSL/"+FILE+ORDER+".pcap");
    private ReadPacketByOrder2() {}
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filename = "SSL_train.txt";
        String filename1 = "SSL_test.txt";
        File file = new File(filename);
        File file1 = new File(filename1);
        PrintWriter writer = null;
        PrintWriter writer1 = null;
        DecimalFormat df = new DecimalFormat("###.0");
        try {
            writer = new PrintWriter(new FileOutputStream(file));
            writer1 = new PrintWriter(new FileOutputStream(file1));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
//        int []a = {0,0,0,0,0,0};
//        for (int j = 0;j < 6;j++){
//            a[j] = 1;
//            for (int m = 0;m < 5000;m++){
//                writer.print(df.format(a[0]));
//                writer.print(' ');
//                writer.print(df.format(a[1]));
//                writer.print(' ');
//                writer.print(df.format(a[2]));
//                writer.print(' ');
//                writer.print(df.format(a[3]));
//                writer.print(' ');
//                writer.print(df.format(a[4]));
//                writer.print(' ');
//                writer.print(df.format(a[5]));
//                writer.println();
//            }
//            a[j] = 0;
//        }
        for (int n = 0; n < COUNT; n++) {
            PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/SSL/"+FILE+ORDER+".pcap");
            PcapHandle handle;
            TcpPort srcTcpPort,dstTcpPort;
            UdpPort srcUdpPort,dstUdpPort;
            double srcPort= 0;
            double dstPort= 0;
            double preTimeTample = 0;
            double timetample = 0;
            double interarricval = 0;
            double tcpWindow = 0;
            int type = 0;
            int i = 0;
            try {
                handle = Pcaps.openOffline(PCAP_FILE);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
            }
            //计算流的各项指标
            for (i=0 ;i < 800;i ++){
                try {
                    Packet packet = handle.getNextPacketEx();
                    timetample = (double) handle.getTimestampInts() * 1000000 + handle.getTimestampMicros();
                    interarricval = timetample - preTimeTample;
                    preTimeTample = timetample;
                    if (packet.contains(TcpPacket.class)){
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        srcTcpPort = tcpPacket.getHeader().getSrcPort();
                        dstTcpPort = tcpPacket.getHeader().getDstPort();
                        tcpWindow = tcpPacket.getHeader().getWindowAsInt();
                        type = 0;
                        srcPort = srcTcpPort.valueAsInt();
                        dstPort = dstTcpPort.valueAsInt();
                    }
                    else if (packet.contains(UdpPacket.class)){
                        UdpPacket udpPacket = packet.get(UdpPacket.class);
                        srcUdpPort = udpPacket.getHeader().getSrcPort();
                        dstUdpPort = udpPacket.getHeader().getDstPort();
                        tcpWindow = 0;
                        type = 1;
                        srcPort = srcUdpPort.valueAsInt();
                        dstPort = dstUdpPort.valueAsInt();
                    }
                    writer.print(df.format(srcPort));
                    writer.print(',');
                    writer.print(df.format(dstPort));
                    writer.print(',');
                    writer.print(df.format(tcpWindow));
                    writer.print(',');
                    writer.print(df.format(interarricval));
                    writer.print(',');
                    writer.print(5);
                    writer.println();
                    System.out.print(ORDER);
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    System.out.println("EOF");
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }catch (NullPointerException e){
                    System.out.println("AAA");
                }
            }
            for (i=0 ;i < 160;i ++){
                try {
                    Packet packet = handle.getNextPacketEx();
                    timetample = (double) handle.getTimestampInts() * 1000000 + handle.getTimestampMicros();
                    interarricval = timetample - preTimeTample;
                    preTimeTample = timetample;
                    if (packet.contains(TcpPacket.class)){
                        TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        srcTcpPort = tcpPacket.getHeader().getSrcPort();
                        dstTcpPort = tcpPacket.getHeader().getDstPort();
                        tcpWindow = tcpPacket.getHeader().getWindowAsInt();
                        type = 0;
                        srcPort = srcTcpPort.valueAsInt();
                        dstPort = dstTcpPort.valueAsInt();
                    }
                    else if (packet.contains(UdpPacket.class)){
                        UdpPacket udpPacket = packet.get(UdpPacket.class);
                        srcUdpPort = udpPacket.getHeader().getSrcPort();
                        dstUdpPort = udpPacket.getHeader().getDstPort();
                        tcpWindow = 0;
                        type = 1;
                        srcPort = srcUdpPort.valueAsInt();
                        dstPort = dstUdpPort.valueAsInt();
                    }
                    writer1.print(df.format(srcPort));
                    writer1.print(',');
                    writer1.print(df.format(dstPort));
                    writer1.print(',');
                    writer1.print(df.format(tcpWindow));
                    writer1.print(',');
                    writer1.print(df.format(interarricval));
                    writer1.print(',');
                    writer1.print(5);
                    writer1.println();
                    System.out.print(ORDER);
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }catch (NullPointerException e){
                    System.out.println("AAA");
                }
            }
//                    writer.print(df.format(len));
//                    writer.print(' ');
//                    writer.print(df.format(type));
//                    System.out.print("源端口：" + srcPort );
//                    System.out.print("目的端口：" + dstPort);
//                    System.out.print("TCP窗口大小：" + tcpWindow);
//                    System.out.print("平均到达时间间隔：" + interarricval + "微秒");//4.8186777E7,1.306811573E9,7.0507805E7,1.337192329E9,8.1663159E7,1.352382707E9
//                    System.out.print("负载长度：" + len);
//                    System.out.println("传输协议：" + type);
            handle.close();
            ORDER++;
        }
        if (writer != null){
            writer.close();
            writer1.close();
        }
    }
}
