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

public class ReadPacketByOrder3 {
    private static final String PCAP_FILE_KEY
            = ReadPacketByOrder3.class.getName() + ".pcapFile";
    private static final String FILE="ssl_";
    private static final String FILEPATH="SSL";
    private static final int LABEL=5;

    private static int ORDER=1;//起始文件标号
    private static int COUNT=100;//循环检测的pcap文件数量
    private static String PCAP_FILE
            = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/"+FILEPATH+"/"+FILE+ORDER+".pcap");
    private ReadPacketByOrder3() {}
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        String filename = FILEPATH+"_Iden+IP+Port+Nums+Window_train.txt";
        String filename1 = FILEPATH+"_Iden+IP+Port+Nums+Window_test.txt";
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
            PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "H:/ispdsl/new_pcap/"+FILEPATH+"/"+FILE+ORDER+".pcap");
            PcapHandle handle;
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
                    byte []a = packet.getRawData();
//                    System.out.println(Arrays.toString(a));
                    for (int j = 22;j<24;j++){
                        writer.print(df.format(a[j]));
                        writer.print(',');
                    }
                    for (int j = 30;j<50;j++){
                        writer.print(df.format(a[j]));
                        writer.print(',');
                    }
                    for (int j = 52;j<54;j++){
                        writer.print(df.format(a[j]));
                        writer.print(',');
                        if (j == 53){
                            writer.println(LABEL);
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
            for (i=0 ;i < 160;i ++){
                try {
                    Packet packet = handle.getNextPacketEx();
                    byte []a = packet.getRawData();
                    for (int j = 22;j<24;j++){
                        writer1.print(df.format(a[j]));
                        writer1.print(',');
                    }
                    for (int j = 30;j<50;j++){
                        writer1.print(df.format(a[j]));
                        writer1.print(',');
                    }
                    for (int j = 52;j<54;j++){
                        writer1.print(df.format(a[j]));
                        writer1.print(',');
                        if (j == 53){
                            writer1.println(LABEL);
                        }
                    }
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


