package com.bestwaiting.aes;

import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESED {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			byte[] key=GeneralIv("sanbian");
			System.out.println(bytesToHexString(key));
			byte[] iv=GeneralIv("majiang");
			System.out.println(bytesToHexString(iv));
			String str="test";
			System.out.println("加密信息："+Encrypt(str, key, iv));
			System.out.println("解密信息："+Decrypt(Encrypt(str, key, iv), key, iv));
			String str1="胡，34；5654大概豆腐干地方官梵蒂冈 豆腐干大概大概的豆腐干大幅度刚刚 ";
			System.out.println("加密信息："+Encrypt(str1, key, iv));
			System.out.println("解密信息："+Decrypt(Encrypt(str1, key, iv), key, iv));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	/**
	 * 提供密钥和向量进行加密
	 * @param sSrc
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 */
	public static String Encrypt(String sSrc, byte[] key, byte[] iv) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// "算法/模式/补码方式"
		IvParameterSpec _iv = new IvParameterSpec(iv);// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, _iv);
		System.out.println(sSrc.getBytes("utf-8").length);
		byte[] encrypted = cipher.doFinal(sSrc.getBytes("utf-8"));
		System.out.println(encrypted.length);
		return Base64.getEncoder().encodeToString(encrypted);
	}
	/**
	 * 提供密钥和向量进行解密
	 * @param sSrc
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 */
	public static String Decrypt(String sSrc, byte[] key, byte[] iv) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec _iv = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, _iv);
		byte[] encrypted = Base64.getDecoder().decode(sSrc);
		byte[] original = cipher.doFinal(encrypted);
		return new String(original, "utf-8");
	}
	/**
	 * 构建密钥字节码
	 * @param keyStr
	 * @return
	 * @throws Exception
	 */
	private static byte[] GeneralKey(String keyStr) throws Exception {
		byte[] bytes = keyStr.getBytes("utf-8");
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(bytes);
		return md.digest();
	}
	/**
	 * 构建加解密向量字节码
	 * @param keyStr
	 * @return
	 * @throws Exception
	 */
	private static byte[] GeneralIv(String keyStr) throws Exception {
		byte[] bytes = keyStr.getBytes("utf-8");
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(bytes);
		return md.digest();
	}
	/**
	 * byte转为16进制
	 * @param src
	 * @return
	 */
	public static String bytesToHexString(byte[] src) {  
        StringBuilder stringBuilder = new StringBuilder("");  
        if (src == null || src.length <= 0) {  
            return null;  
        }  
        for (int i = 0; i < src.length; i++) {  
            int v = src[i] & 0xFF;  
            String hv = Integer.toHexString(v);  
            stringBuilder.append("0x");
            if (hv.length() < 2) {  
                stringBuilder.append(0);  
            }  
            stringBuilder.append(hv.toUpperCase()+",");  
        }  
        return stringBuilder.toString();  
    }  
}
