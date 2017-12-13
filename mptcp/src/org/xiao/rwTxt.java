package org.xiao;
import java.io.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.text.DecimalFormat;

public class rwTxt {
    private static final int LABEL = 5;
    private static final String APP = "google";

    public static void main(String[] args){
        //从txt文件中读取数据,每行15个数据，srcIP(4),dstIP(4),srcPort,dstPort,Win,Dir,payload,time,label
        String filePath = "Comnet-14"+"_IP_train.txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []la = {0,0,0,0,0,0};
        //向txt文件中写入数据
        String filename = "Comnet-14"+"_IP_Rtrain.txt";
        String filename1 = "Comnet-14"+"_IP_Rtrain_label.txt";
        PrintWriter writertest = null;
        PrintWriter writertrain = null;
        DecimalFormat df = new DecimalFormat("###.0");

        int rowNum = 0;
        try {
            File file = new File(filePath);
            File writetestfile = new File(filename);
            File writetrainfile = new File(filename1);
            try {
                writertest = new PrintWriter(new FileOutputStream(writetestfile));
                writertrain = new PrintWriter(new FileOutputStream(writetrainfile));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = null;
                isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
                while ((lineTxt = br.readLine()) != null) {
                    rowNum++;
//            for (int i =0;i<10;i++){
//                System.out.println(lineTxt);
//                lineTxt = br.readLine();
                    s = lineTxt.split(",");
//                    for (int j =0;j<15;j++){
//                        System.out.print(s[j]);
//                    }
                    System.out.println(rowNum);
                    if(rowNum == 1){
                        continue;
                    }
//                    if (rowNum%10==0){
//                        for (int i = 0;i<14;i++){
//                            writertest.print(s[i]);
//                            writertest.print(',');
//                        }
//                        writertest.println(s[14]);
//                    }else {
                    for (int i = 0;i<14;i++){
                        writertest.print(s[i]);
                        writertest.print(' ');
                        if (i == 13){
                            writertest.println();
                        }
                    }
                    switch (Integer.parseInt(s[14])){
                        case 0:
                            writertrain.println(1+" "+0+" "+0+" "+0+" "+0+" "+0);
                            break;
                        case 1:
                            writertrain.println(0+" "+1+" "+0+" "+0+" "+0+" "+0);
                            break;
                        case 2:
                            writertrain.println(0+" "+0+" "+1+" "+0+" "+0+" "+0);
                            break;
                        case 3:
                            writertrain.println(0+" "+0+" "+0+" "+1+" "+0+" "+0);
                            break;
                        case 4:
                            writertrain.println(0+" "+0+" "+0+" "+0+" "+1+" "+0);
                            break;
                        case 5:
                            writertrain.println(0+" "+0+" "+0+" "+0+" "+0+" "+1);
                            break;

                    }
//                        writertrain.println(s[14]);

//                    }
                }
                br.close();
            } else {
                System.out.println("文件不存在!");
            }
        }catch (Exception e) {
            System.out.println("文件读取错误!");
        }
        writertest.close();
        writertrain.close();
    }


}
