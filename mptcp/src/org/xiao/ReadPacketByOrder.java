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
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

public class ReadPacketByOrder {
    private static final String PCAP_FILE_KEY
            = ReadPacketFile.class.getName() + ".pcapFile";
    private static final String FILE="AHD_";
    private static int ORDER=0;//起始文件标号
    private static int COUNT=65;//循环检测的pcap文件数量
    private static String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/AHD/"+FILE+"down_"+ORDER+".pcap");
    private static String PCAP_FILE1
            = System.getProperty(PCAP_FILE_KEY, "H:/AHD/"+FILE+"up_"+ORDER+".pcap");
    private ReadPacketByOrder() {}
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filename = "AHD_output.txt";
        File file = new File(filename);
        PrintWriter writer = null;
        DecimalFormat df = new DecimalFormat("###.000000");
        try {
            writer = new PrintWriter(new FileOutputStream(file));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        for (int n = 0; n < COUNT; n++) {
            PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "H:/AHD/"+FILE+"down_"+ORDER+".pcap");
            PCAP_FILE1 = System.getProperty(PCAP_FILE_KEY, "H:/AHD/"+FILE+"up_"+ORDER+".pcap");
            PcapHandle handle;
            PcapHandle handle1;
            double sum = 0;
            double sum1 = 0;
            double len, len1;
            int[] pck_cnt = new int[1600];
            Arrays.fill(pck_cnt, 0);  //用value值填充全部的arr元素。
            double result = 0;
            double firsttample = 0;
            double lasttample = 0;
            int subcount = 0;
            int i = 0;
            boolean flag = true;
            try {
                handle = Pcaps.openOffline(PCAP_FILE);
                handle1 = Pcaps.openOffline(PCAP_FILE1);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
                handle1 = Pcaps.openOffline(PCAP_FILE1);
            }
            Inet4Address inet4AddressPre = handle.getNextPacket().get(IpV4Packet.class).getHeader().getSrcAddr();
            //计算下行流的各项指标
            while (flag) {
                try {
                    i++;
                    Packet packet = handle.getNextPacketEx();
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    Inet4Address inet4Address = ipV4Packet.getHeader().getSrcAddr();
                    if (i == 1) {
                        firsttample = (double) handle.getTimestampInts() * 1000000 + handle.getTimestampMicros();
                        subcount++;
                    }
                    lasttample = (double) handle.getTimestampInts() * 1000000 + handle.getTimestampMicros();
                    //                UdpPacket udpPacket = packet.get(UdpPacket.class);
                    if (!inet4Address.equals(inet4AddressPre)) {
                        inet4AddressPre = inet4Address;
                        subcount++;
                    }
                    len = ipV4Packet.getHeader().getTotalLengthAsInt() + 14 + 16;
                    pck_cnt[(int) len] = pck_cnt[(int) len] + 1;
                    sum = sum + len;
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }
            }
            //计算上行流的数据量大小
            while (flag) {
                try {
                    Packet packet1 = handle1.getNextPacketEx();
                    IpV4Packet ipV4Packet1 = packet1.get(IpV4Packet.class);
                    len1 = ipV4Packet1.getHeader().getTotalLengthAsInt() + 14 + 16;
                    sum1 = sum1 + len1;
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    continue;
                }
            }
            //计算下行流的熵
            for (int j = 0; j < 1600; j++) {
                if (pck_cnt[j] != 0) {
                    result = result - ((double) pck_cnt[j] / i) * (Math.log((double) pck_cnt[j] / i) / Math.log((double) 2));
//                  System.out.println(pck_cnt[j]);
                }
            }
            writer.print(df.format(sum / sum1));
            writer.print(' ');
            writer.print(df.format((lasttample - firsttample) / i));
            writer.print(' ');
            writer.print(df.format(result));
            writer.print(' ');
            writer.print(df.format(Math.log(subcount)));
            writer.println();
            System.out.print(ORDER);
            System.out.print("比值：" + sum / sum1);
            System.out.print("熵：" + result);
            System.out.print("下行流分段数：" + Math.log(subcount));
            System.out.print("平均到达时间间隔：" + (lasttample - firsttample) / i + "微秒");//4.8186777E7,1.306811573E9,7.0507805E7,1.337192329E9,8.1663159E7,1.352382707E9
            System.out.println(' ');
            handle.close();
            ORDER++;
        }
        if (writer != null){
            writer.close();
        }
    }
}
