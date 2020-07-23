package com.hdd.decrypt;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootApplication
@Slf4j
public class DecryptApplication {

    private static final String Algorithm = "DESede";
    /**
     * 加密文件夹
     */
    @Value("${encryptionFilePath}")
    private String encryptionFilePath;

    @Value("${decodeFilePath}")
    private String decodeFilePath;

    @Value("${isEncrypt}")
    private Boolean isEncrypt;


    public static void main(String[] args) {
        SpringApplication.run(DecryptApplication.class, args);
    }


    @PostConstruct
    private void doTask() {
        if (!isEncrypt) {
            try {
                doDecrypt();
            } catch (FileNotFoundException e) {
                log.error("请填写文件夹路径", e);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        } else {
            // 加密
            try {
                doEncrypt();
            } catch (FileNotFoundException e) {
                log.error("请填写文件夹路径", e);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
    }

    private void doDecrypt() throws FileNotFoundException, UnsupportedEncodingException {
        log.info("系统正在进行解密操作");
        final byte[] keyBytes = "bzyhsbdfbzyhsbdfbzyhsbdf".getBytes();
        File encryFile = new File(encryptionFilePath);
        if (encryFile.exists()) {
            File[] files = encryFile.listFiles();
            int count = 0;
            for (File file : files) {
                count++;
                // 创建解密文件
                String resulrFilePath = decodeFilePath + "/" + file.getName();
                File fileDecryptFile = new File(resulrFilePath);
                if (!fileDecryptFile.exists()) {
                    try {
                        fileDecryptFile.createNewFile();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                FileOutputStream fo = new FileOutputStream(resulrFilePath);
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(fo, "GBK"));
                try {
                    FileReader fileReader = new FileReader(file);
                    BufferedReader bufferedReader = new BufferedReader(fileReader);

                    boolean isFirstLine = true;

                    String str;
                    // 按行读取字符串

                    while ((str = bufferedReader.readLine()) != null) {
                        if (StringUtils.isNotBlank(str)) {
                            String[] splitStr = str.split(",");
                            StringBuilder lineStringResult = new StringBuilder();
                            List<String> tempGetMd5 = new ArrayList<>();
                            for (int i = 0; i < splitStr.length - 1; i++) {
                                // 由于最后一列 是 校验码 ，不需要解密，so length-1
                                String needDecryText = splitStr[i];
                                byte[] srcBytesy = decryptMode(keyBytes, new Base64().decode(needDecryText));
                                String result = new String(srcBytesy, "GBK");
                                lineStringResult.append(result);
                                if (isFirstLine) {
                                    tempGetMd5.add(result);
                                } else {
                                    if (i == 3 || i == 4) {
                                        tempGetMd5.add(result);
                                    }
                                }
                                lineStringResult.append(",");
                            }
                            if (isFirstLine) {
                                tempGetMd5.add(file.getName().split("\\.")[0]);
                                tempGetMd5.add("bz");
                                String collect = tempGetMd5.stream().collect(Collectors.joining(""));

                                String newmd5 = stringToMD5(collect).toUpperCase();
                                lineStringResult.append(newmd5);
                            } else {
                                tempGetMd5.add("bz");
                                String collect = tempGetMd5.stream().collect(Collectors.joining(""));

                                String newmd5 = stringToMD5(collect).toUpperCase();
                                lineStringResult.append(newmd5);
                            }
                            isFirstLine = false;
                            System.out.println(lineStringResult);

                            printWriter.write(lineStringResult + "\r\n");
                        }
                    }
                    bufferedReader.close();
                    fileReader.close();

                } catch (FileNotFoundException e) {
                    log.error("读取文件失败");
                } catch (IOException e) {
                    log.error("读取文件失败IO异常");
                }
                printWriter.close();
                log.info("一个文件解密完成");
            }
        } else {
            log.error("加密文件所在目录为空，请输入");
        }

        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
        log.info("所有文件已经执行完毕，请按CTRL + C 退出 ！！！");
    }

    private void doEncrypt() throws FileNotFoundException, UnsupportedEncodingException {
        log.info("系统正在进行加密操作");
        final byte[] keyBytes = "bzyhsbdfbzyhsbdfbzyhsbdf".getBytes();
        File encryFile = new File(decodeFilePath);
        if (encryFile.exists()) {
            File[] files = encryFile.listFiles();
            int count = 0;
            List<String> tempGetMd5 = new ArrayList<>();
            for (File file : files) {
                count++;
                // 创建加密文件
                String resulrFilePath = encryptionFilePath + "/" + file.getName();
                File fileDecryptFile = new File(resulrFilePath);
                if (!fileDecryptFile.exists()) {
                    try {
                        fileDecryptFile.createNewFile();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                FileOutputStream fo = new FileOutputStream(resulrFilePath);
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(fo, "GBK"));
                try {
                    FileReader fileReader = new FileReader(file);
                    BufferedReader bufferedReader = new BufferedReader(fileReader);
                    boolean isFirstLine = true;
                    String str;
                    // 按行读取字符串
                    while ((str = bufferedReader.readLine()) != null) {
                        if (StringUtils.isNotBlank(str)) {
                            String[] splitStr = str.split(",");
                            StringBuilder lineStringResult = new StringBuilder();// 收集加密后的数据
                            for (int i = 0; i < splitStr.length; i++) {
                                // 由于最后一列 是 校验码 ，不需要解密，so length-1
                                String needDecryText = splitStr[i];
                                if ((i != splitStr.length - 1) && isFirstLine) {
                                    tempGetMd5.add(needDecryText);
                                }

                                if ((i == splitStr.length - 1) && isFirstLine) {
                                    continue;
                                }
                                if (!isFirstLine && i == splitStr.length - 1) {
                                    lineStringResult.append(needDecryText.toUpperCase());
                                    continue;
                                }
                                byte[] srcBytesy = encryptMode(keyBytes, needDecryText.getBytes());

                                String result = new Base64().encodeAsString(srcBytesy);
                                lineStringResult.append(result);
                                if (i != splitStr.length - 1) {
                                    lineStringResult.append(",");
                                }
                            }
                            if (isFirstLine) {
                                tempGetMd5.add(file.getName().split("\\.")[0]);
                                tempGetMd5.add("bz");
                                String collect = tempGetMd5.stream().collect(Collectors.joining(""));

                                String newmd5 = stringToMD5(collect).toUpperCase();
                                lineStringResult.append(newmd5);
                            }
                            isFirstLine = false;
                            System.out.println(lineStringResult);

                            printWriter.write(lineStringResult + "\r\n");
                        }
                    }

                    bufferedReader.close();
                    fileReader.close();

                } catch (FileNotFoundException e) {
                    log.error("读取文件失败");
                } catch (IOException e) {
                    log.error("读取文件失败IO异常");
                }
                printWriter.close();
                log.info("一个文件解密完成");
            }
        } else {
            log.error("加密文件所在目录为空，请输入");
        }


    }

    public static byte[] decryptMode(byte[] keybyte, byte[] src) {
        try {
            // ????
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // ??
            Cipher c1 = Cipher.getInstance(Algorithm);
            // Cipher c1 = Cipher.getInstance("DES/ECB/NoPadding");
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    public static byte[] encryptMode(byte[] keybyte, byte[] src) {
        try {
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            Cipher c1 = Cipher.getInstance(Algorithm);
            // Cipher c1 = Cipher.getInstance("DES/ECB/NoPadding");
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    public static String stringToMD5(String plainText) {
        byte[] secretBytes = null;
        try {
            secretBytes = MessageDigest.getInstance("md5").digest(
                    plainText.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("没有这个md5算法！");
        }
        String md5code = new BigInteger(1, secretBytes).toString(16);
        for (int i = 0; i < 32 - md5code.length(); i++) {
            md5code = "0" + md5code;
        }
        return md5code;
    }
}
