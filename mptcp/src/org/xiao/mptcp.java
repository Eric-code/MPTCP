package org.xiao;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * Created by xiao on 27/05/14.
 */
public class mptcp {
    static final Logger log = LoggerFactory.getLogger(mptcp.class);

    private static final int COUNT = 1;
    private static final String PCAP_FILE
            =  "/Users/xiao/Desktop/mptcp-assignment.pcap";
    private static String Multipath_TCP = "30";

    private static final int MP_CAPABLE = 0;
    private static final int MP_JOIN = 1;
    private static final int DSS = 2;
    private static final int ADD_ADDR = 3;
    private static final int REMOVE_ADDR = 4;
    private static final int MP_PRIO = 5;
    private static final int MP_FAIL = 6;
    private static final int MP_FASTCLOSE = 7;

    private static final int JOIN_OPTION_1st = 12;
    private static final int JOIN_OPTION_2nd = 16;
    private static final int JOIN_OPTION_3rd = 24;

    private static final int CAPABLE_OPTION_1st_and_2nd = 12;
    private static final int CAPABLE_OPTION_3rd = 20;

    private static int CONTROL_NUMBER = 4;

    private static List<String> toHexData(byte[] data){
//        StringBuilder sb = new StringBuilder();
//        for(byte x : data){
//            sb.append(String.format("%02X ", x));
//        }
//        return sb.toString();
        List<String> hexResult = new LinkedList<String>();
        for(byte x : data){
            hexResult.add(String.format("%02X", x));
        }
        return hexResult;

    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapHandle handle = Pcaps.openOffline(PCAP_FILE);
        Packet packet = null;
        try {
            packet = handle.getNextPacketEx();
        } catch (EOFException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            e.printStackTrace();
        }

        int control = 0;

        int counter = 0;
        int capableCounter = 0;
        int joinCounter = 0;
        while (packet != null) {
//            Timestamp ts = new Timestamp(handle.getTimestampInts() * 1000L);
//            ts.setNanos(handle.getTimestampMicros() * 1000);
//            System.out.println(ts);

//            System.out.println(handle.getTimestampMicros());
            counter ++;
//            System.out.println(counter);
            TcpPacket tcp_Packet = packet.get(TcpPacket.class);
            // reinitialize packet
            Packet packet1 = packet;
            packet = null;
            // maybe ARP
            if(tcp_Packet == null){
                // Get next packet
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException e) {
                    //e.printStackTrace();
                } catch (TimeoutException e) {
                    e.printStackTrace();
                }

                continue;
            }
            List<TcpPacket.TcpOption> tcp_options = tcp_Packet.getHeader().getOptions();
            for(int j = 0; j< tcp_options.size();j++){
                if(tcp_options.get(j).getKind().valueAsString().equals(Multipath_TCP)){
                    int optionLength = tcp_options.get(j).length();
//                    System.out.println("Length = " + optionLength);
                    byte[] data = tcp_options.get(j).getRawData();
//                    for(byte b : data){
//                        System.out.print(b + " ");
//                    }
                    List<String> mpTcpHexData = toHexData(data);
                    String mptcpSubtype = mpTcpHexData.get(2).substring(0,1);
//                    System.out.println("\nThe Hex data is : " + mpTcpHexData);
//                    System.out.println("The mptcpSegment = " + mptcpSubtype);
                    switch (Integer.parseInt(mptcpSubtype)){
                        case MP_CAPABLE: {
                            capableCounter++;

                            System.out.print(counter +" : ");
                            System.out.print("MP_CAPABLE : ");
                            System.out.println("from "+ packet1.get(IpV4Packet.class).getHeader().getSrcAddr()
                                    + " to "+ packet1.get(IpV4Packet.class).getHeader().getDstAddr());

                            switch (optionLength){
                                case CAPABLE_OPTION_1st_and_2nd:{
                                    String senderKey = mpTcpHexData.get(4) + mpTcpHexData.get(5)
                                            + mpTcpHexData.get(6) + mpTcpHexData.get(7)
                                            + mpTcpHexData.get(8) + mpTcpHexData.get(9)
                                            + mpTcpHexData.get(10) + mpTcpHexData.get(11);
                                    System.out.println("\t sender's key = " + senderKey);
                                    break;
                                }
                                case CAPABLE_OPTION_3rd:{
                                    String senderKey = mpTcpHexData.get(4) + mpTcpHexData.get(5)
                                            + mpTcpHexData.get(6) + mpTcpHexData.get(7)
                                            + mpTcpHexData.get(8) + mpTcpHexData.get(9)
                                            + mpTcpHexData.get(10) + mpTcpHexData.get(11);
                                    System.out.println("\t sender's Key = " + senderKey);
                                    String receiverKey = mpTcpHexData.get(12) + mpTcpHexData.get(13)
                                            + mpTcpHexData.get(14) + mpTcpHexData.get(15)
                                            + mpTcpHexData.get(16) + mpTcpHexData.get(17)
                                            + mpTcpHexData.get(18) + mpTcpHexData.get(19);
                                    System.out.println("\t receiver's Key = " + receiverKey);

                                    if(capableCounter%3 == 0){
                                        System.out.println(" ");
                                    }

                                    break;
                                }
                                default:{
                                    System.out.println("no such capable length!");
                                }
                            }


                            break;
                        }
                        case MP_JOIN:{
                            joinCounter++;
                            System.out.print(counter + " : ");
                            System.out.print("MP_JOIN : ");
                            System.out.println("from " + packet1.get(IpV4Packet.class).getHeader().getSrcAddr()
                                    + " to " + packet1.get(IpV4Packet.class).getHeader().getDstAddr());

                            switch (optionLength){
                                case JOIN_OPTION_1st:{
                                    String token = mpTcpHexData.get(4) + mpTcpHexData.get(5)
                                            + mpTcpHexData.get(6) + mpTcpHexData.get(7);
                                    System.out.println("\t Join 1st: B's token = " + token);
                                    break;
                                }
                                case JOIN_OPTION_2nd:{
                                    String senderTruncatedMAC = mpTcpHexData.get(5) + mpTcpHexData.get(6)
                                            + mpTcpHexData.get(7) + mpTcpHexData.get(8)
                                            + mpTcpHexData.get(9) + mpTcpHexData.get(10)
                                            + mpTcpHexData.get(11) + mpTcpHexData.get(12);
                                    System.out.println("\t Join 2nd: B's (Truncated) HMAC = " + senderTruncatedMAC);
                                    break;
                                }
                                case JOIN_OPTION_3rd:{
                                    String senderHMAC = mpTcpHexData.get(4) + mpTcpHexData.get(5)
                                            + mpTcpHexData.get(6) + mpTcpHexData.get(7)
                                            + mpTcpHexData.get(8) + mpTcpHexData.get(9)
                                            + mpTcpHexData.get(10) + mpTcpHexData.get(11)
                                            + mpTcpHexData.get(12) + mpTcpHexData.get(13)
                                            + mpTcpHexData.get(14) + mpTcpHexData.get(15)
                                            + mpTcpHexData.get(16) + mpTcpHexData.get(17)
                                            + mpTcpHexData.get(18) + mpTcpHexData.get(19)
                                            + mpTcpHexData.get(20) + mpTcpHexData.get(21)
                                            + mpTcpHexData.get(22) + mpTcpHexData.get(23);
                                    System.out.println("\t Join 3rd: A's HMAC = " + senderHMAC);

                                    if(joinCounter%3 == 0){
                                        System.out.println(" ");
                                    }

                                    break;
                                }
                                default:{
                                    System.out.println("no such join length!");
                                }
                            }

                            break;
                        }
                        case DSS:{
//                            System.out.println("DSS");
                            break;
                        }
                        case ADD_ADDR:{
//                            System.out.println(counter);
//                            System.out.println("ADD_ADDR");
//                            System.out.println("from "+ packet1.get(IpV4Packet.class).getHeader().getSrcAddr()
//                                    + " to "+ packet1.get(IpV4Packet.class).getHeader().getDstAddr());
                            break;
                        }
                        case REMOVE_ADDR:{
                            System.out.println(counter);
                            System.out.println("REMOVE_ADDR");
                            break;
                        }
                        case MP_PRIO:{
                            System.out.println(counter);
                            System.out.println("MP_PRIO");
                            break;
                        }
                        case MP_FAIL:{
                            System.out.println(counter);
                            System.out.println("MP_FAIL");
                            break;
                        }
                        case MP_FASTCLOSE:{
                            System.out.println(counter);
                            System.out.println("MP_FASTCLOSE");
                            break;
                        }
                        default : {
                            System.out.println("!!! not matched !!!");
                        }
                    }

                }
            }
            // Get next packet
            try {
                packet = handle.getNextPacketEx();
            } catch (EOFException e) {
                //e.printStackTrace();
            } catch (TimeoutException e) {
                e.printStackTrace();
            }

            // n-time test
//            control++;
//            if(control == CONTROL_NUMBER){
//                packet = null;
//            }
        }
        System.out.println("\n\nMPTCP capable counter = " + capableCounter / 3);
        System.out.println("MPTCP join counter = " + joinCounter / 3);
        handle.close();
    }
}

