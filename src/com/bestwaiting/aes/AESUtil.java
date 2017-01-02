package com.bestwaiting.aes;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
/**
 * AES加解密操作 2016/11/28
 * @author bestwaiting
 * 目前采用128位，256位需要更换jdk中的jar包
 */
public class AESUtil {
	public static void main(String[] args) throws Exception {
		System.out.println(bytesToHexString(General128("****")));
		System.out.println(bytesToHexString(General128("****")));
	}
	private static final byte[] KEY={0x0A,(byte) 0x99,(byte) 0xC5,0x32,(byte) 0x95,(byte) 0x89,(byte) 0xAD,0x36,0x69,0x0C,
		(byte) 0xC7,(byte) 0xEC,0x49,0x00,(byte) 0xE2,0x20};
	private static final byte[] IV={0x08,(byte) 0xBC,(byte) 0xC3,0x2C,0x40,0x25,0x41,(byte) 0xE0,(byte) 0xD4,(byte) 0x90,
		(byte) 0xA4,0x04,(byte) 0xFC,(byte) 0xD4,(byte) 0xB5,(byte) 0xEA};
	/**
	 * 128位加密信息
	 * @param data
	 * @return
	 */
	public static byte[] Encrypt(byte[] data){
		try {
			return Encrypt(data,KEY,IV);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e.toString());
		}
		return null;
	}
	/**
	 * 128位解密信息
	 * @param data
	 * @return
	 */
	public static byte[] Decrypt(byte[] data){
		try {
			return Decrypt(data,KEY,IV);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e.toString());
		}
		return null;
	}
	/**
	 * 提供密钥和向量进行加密
	 * @param data
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 */
	private static byte[] Encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");// "算法/模式/补码方式"
		IvParameterSpec _iv = new IvParameterSpec(iv);// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, _iv);
		byte[] encrypted = cipher.doFinal(data);
		return encrypted;
	}
	/**
	 * 提供密钥和向量进行解密
	 * @param data
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 */
	private static byte[] Decrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec _iv = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, _iv);
		byte[] original = cipher.doFinal(data);
		return original;
	}
	/**
	 * 构建密钥字节码256
	 * @param keyStr
	 * @return
	 * @throws Exception
	 */
	private static byte[] General256(String keyStr) throws Exception {
		byte[] bytes = keyStr.getBytes("utf-8");
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(bytes);
		return md.digest();
	}
	/**
	 * 构建加解密向量字节码128
	 * @param keyStr
	 * @return
	 * @throws Exception
	 */
	private static byte[] General128(String keyStr) throws Exception {
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
	private static String bytesToHexString(byte[] src) {  
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
        if (stringBuilder.length()>2) {
        	return stringBuilder.substring(0, stringBuilder.length()-1);
		}
        return stringBuilder.toString();  
    }  
}
