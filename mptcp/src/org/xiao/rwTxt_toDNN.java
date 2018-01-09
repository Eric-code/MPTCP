package org.xiao;
import java.io.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.text.DecimalFormat;
import java.util.Arrays;

public class rwTxt_toDNN {
    private static final String APP = "";

    //获取一行所有数据，原始数据54+方向+时间间隔+包字节数+标签
    public static void getall(){
        String filePath = "Comnet-14_all"+APP+".txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []la = {0,0,0,0,0,0};
        //向txt文件中写入数据
        String filename = "Comnet_"+APP+"_test.txt";
        String filename1 = "Comnet_"+APP+"_train.txt";
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
                    System.out.println(rowNum);
                    s = lineTxt.split(",");
                    if (rowNum % 10 == 0){
                        for (int i = 0;i<57;i++){
                            writertest.print(s[i]);
                            writertest.print(',');
                        }
                        writertest.println(Integer.valueOf(s[57]));
                    }else {
                        for (int i = 0;i<57;i++){
                            writertrain.print(s[i]);
                            writertrain.print(',');
                        }
                        writertrain.println(Integer.valueOf(s[57]));
                    }
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

    public static void getUpDown(){
        String filePath = "Comnet-14_all"+APP+".txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        //向txt文件中写入数据
        String filename = "Comnet_feature_"+APP+"_test.txt";
        String filename1 = "Comnet_feature_"+APP+"_train.txt";
        PrintWriter writertest = null;
        PrintWriter writertrain = null;
        DecimalFormat df = new DecimalFormat("###.0000");

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
                for (int n = 0;n<220;n++){
                    double uplen = 0;
                    double downlen = 0;
                    int upcount = 0;
                    int downcount = 0;
                    double upSum = 0;
                    double downSum = 0;
                    double time = 0;
                    double upsurvive = 0;
                    double downsurvive = 0;
                    double payload = 0;
                    int []pck_cnt = new int[27000];
                    Arrays.fill(pck_cnt,0);  //用value值填充全部的arr元素。
                    double result = 0;
                    for (int m =0;m<500;m++){
                        lineTxt = br.readLine();
                        s = lineTxt.split(",");
                        System.out.println(n+","+m);
                        time += Double.valueOf(s[55]); //包到达时间间隔
                        if (Double.valueOf(s[54])==1){//上行流
                            upcount++;
                            uplen = Double.valueOf(s[56]);//上行流字节数
                            upSum += uplen;
                            payload += uplen-54;//payload长度
                            upsurvive += Double.valueOf(s[22]);//上行流存活时间
                        }else {//下行流
                            downcount++;
                            downlen = Double.valueOf(s[56]);//下行流字节数
                            downSum += downlen;
                            pck_cnt[(int)downlen]=pck_cnt[(int)downlen]+1;
                            payload += downlen-54;//payload长度
                            downsurvive += Double.valueOf(s[22]);//下行流存活时间
                        }
                    }
                    for (int j =0;j<27000;j++){
                        if (pck_cnt[j]!=0){
                            result = result - ((double) pck_cnt[j]/500) * (Math.log((double) pck_cnt[j]/500)/Math.log((double)2));
                        }
                    }
                    writertrain.print(df.format(upSum/downSum));//上下行比值
                    writertrain.print(',');
                    writertrain.print(df.format(result));//上下行信息熵
                    writertrain.print(',');
                    writertrain.print(df.format(payload/500));//payload均值
                    writertrain.print(',');
                    writertrain.print(df.format(upsurvive/upcount));//上行流存活时间均值
                    writertrain.print(',');
                    writertrain.print(df.format(downsurvive/downcount));//下行流存活时间均值
                    writertrain.print(',');
                    writertrain.print(df.format(time/500));//上下行信息熵
                    writertrain.print(',');
                    writertrain.print(s[23]);//协议类型
                    writertrain.print(',');
                    writertrain.println(s[57]);//标签
                }

                for (int n = 0;n<19;n++){
                    double uplen = 0;
                    double downlen = 0;
                    int upcount = 0;
                    int downcount = 0;
                    double upSum = 0;
                    double downSum = 0;
                    double time = 0;
                    double upsurvive = 0;
                    double downsurvive = 0;
                    double payload = 0;
                    int []pck_cnt = new int[27000];
                    Arrays.fill(pck_cnt,0);  //用value值填充全部的arr元素。
                    double result = 0;
                    for (int m =0;m<500;m++){
                        lineTxt = br.readLine();
                        s = lineTxt.split(",");
                        time += Double.valueOf(s[55]); //包到达时间间隔
                        if (Double.valueOf(s[54])==1){//上行流
                            upcount++;
                            uplen = Double.valueOf(s[56]);//上行流字节数
                            upSum += uplen;
                            payload += uplen-54;//payload长度
                            upsurvive += Double.valueOf(s[22]);//上行流存活时间
                        }else {//下行流
                            downcount++;
                            downlen = Double.valueOf(s[56]);//下行流字节数
                            downSum += downlen;
                            pck_cnt[(int)downlen]=pck_cnt[(int)downlen]+1;
                            payload += downlen-54;//payload长度
                            downsurvive += Double.valueOf(s[22]);//下行流存活时间
                        }
                    }
                    for (int j =0;j<27000;j++){
                        if (pck_cnt[j]!=0){
                            result = result - ((double) pck_cnt[j]/500) * (Math.log((double) pck_cnt[j]/500)/Math.log((double)2));
                        }
                    }
                    writertest.print(df.format(upSum/downSum));//上下行比值
                    writertest.print(',');
                    writertest.print(df.format(result));//上下行信息熵
                    writertest.print(',');
                    writertest.print(df.format(payload/500));//payload均值
                    writertest.print(',');
                    writertest.print(df.format(upsurvive/upcount));//上行流存活时间均值
                    writertest.print(',');
                    writertest.print(df.format(downsurvive/downcount));//下行流存活时间均值
                    writertest.print(',');
                    writertest.print(df.format(time/500));//上下行信息熵
                    writertest.print(',');
                    writertest.print(s[23]);//协议类型
                    writertest.print(',');
                    writertest.println(s[57]);//标签
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

    public static void read(){
        String filePath = "Comnet-14_all_dir_train.txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []la = {0,0,0,0,0,0};
        //向txt文件中写入数据
        String filename = "Comnet-14_TCPwithoutIP_Port_train.txt";
        PrintWriter writertest = null;
        DecimalFormat df = new DecimalFormat("###.");

        int rowNum = 0;
        try {
            File file = new File(filePath);
            File writetestfile = new File(filename);
            try {
                writertest = new PrintWriter(new FileOutputStream(writetestfile));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = null;
                isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
                double []num = {0,0,0,0,0,0};
                double []max = {64537.0,64537.0,1.0,26130.0,233.0,65535.0};
                while ((lineTxt = br.readLine()) != null) {
                    rowNum++;
                    System.out.println(rowNum);
                    s = lineTxt.split(",");
                    if ((rowNum>326800)&&(rowNum<434200)){
                        continue;
                    }
                    if (rowNum>649400){
                        break;
                    }
                    for (int i =0;i<26;i++){
                        double a = Double.valueOf(s[i]);
                        int b = new Double(a).intValue();
                        String c = convertToBin(b);
                        writertest.print(convertToBin(new Double(Double.valueOf(s[i])).intValue()));
//                        writertest.print(' ');
                    }
                    for (int i =38;i<54;i++){
                        writertest.print(convertToBin(new Double(Double.valueOf(s[i])).intValue()));
//                        writertest.print(' ');
                    }
                    writertest.println();
//                    double sPort = convert(Double.valueOf(s[34]))*256+convert(Double.valueOf(s[35]));
//                    double dPort = convert(Double.valueOf(s[36]))*256+convert(Double.valueOf(s[37]));
//                    double lenth = convert(Double.valueOf(s[16]))*256+convert(Double.valueOf(s[17]))+14;
//                    writertest.print(df.format(sPort));
//                    writertest.print(',');
//                    writertest.print(df.format(dPort));
//                    writertest.print(',');
//                    if (rowNum<=649400){
//                        writertest.print(s[54]);//方向
//                    }else {
//                        if (Double.valueOf(s[23])==6){//TCP
//                            writertest.print(s[54]);
//                        }else if (Double.valueOf(s[23])==17){//UDP
//                            writertest.print(s[42]);
//                        }
//                    }
//                    writertest.print(',');
//                    writertest.print(df.format(lenth));//payload
//                    writertest.print(',');
//                    writertest.print(df.format(convert(Double.valueOf(s[22]))));
//                    writertest.print(',');
//                    if (Double.valueOf(s[23])==6){//TCP
//                        double windowsize = convert(Double.valueOf(s[48]))*256+convert(Double.valueOf(s[49]));
//                        writertest.println(df.format(windowsize));
//                    }else if (Double.valueOf(s[23])==17){//UDP
//                        writertest.println(df.format(0));
//                    }
//                    if (rowNum<=649400){
//                        writertest.println(Integer.valueOf(s[55]));
//                    }else {
//                        writertest.println(Integer.valueOf(s[43]));
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
    }

    public static double convert(double d){
        if (d<0){
            d = d + 256;
            return d;
        }
        else
            return d;
    }

    public static String convertToBin(int num){
        String binaray = null;
        if (num<0){
            binaray = Integer.toBinaryString(num).substring(24);
        }else{
            String s =  "00000000"+Integer.toBinaryString(9);
            binaray = s.substring(s.length()-8);
        }
        char []chars = {' ',' ',' ',' ',' ',' ',' ',' '};
        for (int i = 0;i<8;i++){
            chars[i] = binaray.charAt(i);
        }
        String s = chars[0]+" "+chars[1]+" "+chars[2]+" "+chars[3]+" "+chars[4]+" "+chars[5]+" "+chars[6]+" "+chars[7]+" ";
        return s;
    }

    public static void filedevide(){
        String filePath = "Comnet-14_all_dir_test.txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []la = {0,0,0,0,0,0};
        //向txt文件中写入数据
        String filename = "Comnet-14_TCPwithoutIP_Port_test.txt";
        String filename1 = "Comnet-14_TCPwithoutIP_Port_test_label.txt";
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
                    System.out.println(rowNum);
                    s = lineTxt.split(",");
                    if ((rowNum>32700)&&(rowNum<45100)){
                        continue;
                    }
                    if (rowNum>69600){
                        break;
                    }
                    if (rowNum%10==0){
                        for (int i =0;i<26;i++){
                            writertest.print(convertToBin(new Double(Double.valueOf(s[i])).intValue()));
//                        writertest.print(' ');
                        }
                        for (int i =38;i<54;i++){
                            writertest.print(convertToBin(new Double(Double.valueOf(s[i])).intValue()));
//                        writertest.print(' ');
                        }
                        writertest.println();
                        switch (Integer.parseInt(s[55])){
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
                    }
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

    public static void writetoCRNN(){
        String filePath = "Comnet-14_all_dir_test.txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []la = {0,0,0,0,0,0};
        //向txt文件中写入数据
        String filename = "Comnet-14_all_withoutIP+Port_CNN_test.txt";
        String filename1 = "Comnet-14_all_withoutIP+Port_CNN_test_label.txt";
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
                for (int m = 0;m<696;m++){
                    for (int i = 0;i<99;i++){
                        lineTxt = br.readLine();
                        rowNum++;
                        System.out.println(rowNum);
                        s = lineTxt.split(",");
                        for (int j = 0;j<26;j++){
                            writertest.print(df.format(convert(Double.valueOf(s[j]))));
                            writertest.print(' ');
                        }
                        for (int j = 38;j<54;j++){
                            writertest.print(df.format(convert(Double.valueOf(s[j]))));
                            writertest.print(' ');
                        }
//                        writertest.print(df.format(convert(Double.valueOf(s[54]))));
//                        writertest.print(' ');
                    }
                    lineTxt = br.readLine();
                    rowNum++;
                    System.out.println(rowNum);
                    s = lineTxt.split(",");
                    for (int j = 0;j<26;j++){
                        writertest.print(df.format(convert(Double.valueOf(s[j]))));
                        writertest.print(' ');
                    }
                    for (int j = 38;j<53;j++){
                        writertest.print(df.format(convert(Double.valueOf(s[j]))));
                        writertest.print(' ');
                    }
                    writertest.println(df.format(convert(Double.valueOf(s[53]))));
                }
                for (int n =0;n<118;n++){
                    writertrain.println(1+" "+0+" "+0+" "+0+" "+0+" "+0);
                }
                for (int n =0;n<94;n++){
                    writertrain.println(0+" "+1+" "+0+" "+0+" "+0+" "+0);
                }
                for (int n =0;n<115;n++){
                    writertrain.println(0+" "+0+" "+1+" "+0+" "+0+" "+0);
                }
                for (int n =0;n<124;n++){
                    writertrain.println(0+" "+0+" "+0+" "+1+" "+0+" "+0);
                }
                for (int n =0;n<136;n++){
                    writertrain.println(0+" "+0+" "+0+" "+0+" "+1+" "+0);
                }
                for (int n =0;n<109;n++){
                    writertrain.println(0+" "+0+" "+0+" "+0+" "+0+" "+1);
                }
//                for (int n =0;n<1058;n++){
//                    writertrain.println(0+" "+0+" "+0+" "+0+" "+0+" "+0+" "+1);
//                }
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

    public static void OneHot(){
        String filePath = "Comnet-14_all_test_new.txt";
        String lineTxt = null;
        String []s = {null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null};
        int []a = new int[256];
        int []la = new int[7];
        //向txt文件中写入数据
        String filename = "Comnet-14_flow_onehot_withoutIP_test.txt";
        String filename1 = "Comnet-14_flow_onehot_test_label.txt";
        PrintWriter writer = null;
        PrintWriter labelwriter = null;
        DecimalFormat df = new DecimalFormat("###.0");

        int rowNum = 0;
        try {
            File file = new File(filePath);
            File writetestfile = new File(filename);
            File writelabelfile = new File(filename1);
            try {
                writer = new PrintWriter(new FileOutputStream(writetestfile));
                labelwriter = new PrintWriter(new FileOutputStream(writelabelfile));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
            if(file.isFile() && file.exists()) {
                InputStreamReader isr = null;
                isr = new InputStreamReader(new FileInputStream(file), "utf-8");
                BufferedReader br = new BufferedReader(isr);
                double count = 0;
                while ((lineTxt = br.readLine()) != null) {
                    Arrays.fill(a,0);  //用value值填充全部的arr元素
                    Arrays.fill(la,0);
                    rowNum++;
                    System.out.println(rowNum);
                    if (rowNum%10==0){
                        s = lineTxt.split(",");
                        for (int i =0;i<26;i++){
                            Arrays.fill(a,0);
                            double num = convert(Double.valueOf(s[i]));
                            a[(int)num] = 1;
                            for (int j = 0;j<256;j++){
                                writer.print(a[j]);
                                writer.print(' ');
                            }
                            writer.println();
                        }
                        for (int i =34;i<54;i++){
                            Arrays.fill(a,0);
                            double num = convert(Double.valueOf(s[i]));
                            a[(int)num] = 1;
                            for (int j = 0;j<256;j++){
                                writer.print(a[j]);
                                writer.print(' ');
                            }
                            writer.println();
                        }
                        double label = Double.valueOf(s[54]);
                        la[(int)label] = 1;
                        for (int n = 0;n<5;n++){
                            labelwriter.print(la[n]);
                            labelwriter.print(' ');
                        }
                        labelwriter.println(la[5]);
                    }else {
                        continue;
                    }
                }
                br.close();
            } else {
                System.out.println("文件不存在!");
            }
        }catch (Exception e) {
            System.out.println("文件读取错误!");
        }
        writer.close();
        labelwriter.close();
    }

    public static void main(String[] args){
        filedevide();
    }

}

