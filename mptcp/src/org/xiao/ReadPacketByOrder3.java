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

public class ReadPacketByOrder3 {
    private static final String PCAP_FILE_KEY
            = ReadPacketByOrder3.class.getName() + ".pcapFile";
    private static final String FILE="ssl_";
    private static int ORDER=1;//起始文件标号
    private static int COUNT=100;//循环检测的pcap文件数量
    private static String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/SSL/"+FILE+ORDER+".pcap");
    private ReadPacketByOrder3() {}
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
        for (int n = 0; n < COUNT; n++) {
            PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/SSL/"+FILE+ORDER+".pcap");
            PcapHandle handle;
            int i = 0;
            try {
                handle = Pcaps.openOffline(PCAP_FILE);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
            }
            //计算流的各项指标
            for (i=0 ;i < 80;i ++){
                try {
                    Packet packet = handle.getNextPacketEx();
                    byte []a = packet.getRawData();
//                    System.out.println(Arrays.toString(a));
                    for (int j = 0;j<80;j++){
                        writer.print(df.format(a[j]));
                        writer.print(',');
                        if (j == 79){
                            writer.print(6);
                            writer.println();
                        }
                    }
//                    if (((i+1) % 16 == 0) && ((i+1) % 800 != 0) ){
//                        writer.print(1);
//                        writer.println();
//                    }
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }catch (NullPointerException e){
                }
                System.out.print(ORDER);
            }
            for (i=0 ;i < 16;i ++){
                try {
                    Packet packet = handle.getNextPacketEx();
                    byte []a = packet.getRawData();
                    for (int j = 0;j<80;j++){
                        writer1.print(df.format(a[j]));
                        writer1.print(',');
                        if (j == 79){
                            writer1.print(6);
                            writer1.println();
                        }
                    }
//                    if (((i+1) % 16 == 0) && ((i+1) % 160 != 0) ){
//                        writer1.print(1);
//                        writer1.println();
//                    }
                } catch (TimeoutException e) {
                } catch (EOFException e) {
                    break;
                }catch (IllegalArgumentException e){
                    System.out.println("AAA");
                    continue;
                }catch (NullPointerException e){
                }
            }
//            writer.println();
//            writer1.println();
            handle.close();
            ORDER++;
        }
        if (writer != null){
            writer.close();
            writer1.close();
        }
    }
}


