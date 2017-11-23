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
        String filename = "SSL_output2.txt";
        File file = new File(filename);
        PrintWriter writer = null;
        DecimalFormat df = new DecimalFormat("###.000000");
        try {
            writer = new PrintWriter(new FileOutputStream(file));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
//        int []a = {0,0,0,0,0,0};
//        for (int j = 0;j < 6;j++){
//            a[j] = 1;
//            for (int m = 0;m < 100;m++){
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
            int len = 0;
            int type = 0;
            int i = 0;
            boolean flag = true;
            try {
                handle = Pcaps.openOffline(PCAP_FILE);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
            }
            //计算流的各项指标
            for (i=0 ;i < 22;i ++){
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
                        len = tcpPacket.getPayload().length();
                    }
                    else if (packet.contains(UdpPacket.class)){
                        UdpPacket udpPacket = packet.get(UdpPacket.class);
                        srcUdpPort = udpPacket.getHeader().getSrcPort();
                        dstUdpPort = udpPacket.getHeader().getDstPort();
                        tcpWindow = 0;
                        type = 1;
                        srcPort = srcUdpPort.valueAsInt();
                        dstPort = dstUdpPort.valueAsInt();
                        len = udpPacket.getPayload().length();
                    }
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }catch (NullPointerException e){
                    len = 0;
                }
                if (i > 1){
                    writer.print(df.format(srcPort/65535));
                    writer.print(' ');
                    writer.print(df.format(dstPort/65535));
                    writer.print(' ');
                    writer.print(df.format(tcpWindow/65535));
                    writer.print(' ');
                    writer.print(df.format(interarricval/100000000));
                    writer.print(' ');
//                    writer.print(df.format(len));
//                    writer.print(' ');
//                    writer.print(df.format(type));
                    System.out.print(ORDER);
                    System.out.print("源端口：" + srcPort );
                    System.out.print("目的端口：" + dstPort);
                    System.out.print("TCP窗口大小：" + tcpWindow);
                    System.out.print("平均到达时间间隔：" + interarricval + "微秒");//4.8186777E7,1.306811573E9,7.0507805E7,1.337192329E9,8.1663159E7,1.352382707E9
                    System.out.print("负载长度：" + len);
                    System.out.println("传输协议：" + type);
                }
            }
            writer.println();
            handle.close();
            ORDER++;
        }
        if (writer != null){
            writer.close();
        }
    }
}
