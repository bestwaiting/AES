package com.bestwaiting.aes;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESED_Bouncy {
	public static void main(String[] args) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(out);
		dataOut.writeUTF("test");
		byte[] old=out.toByteArray();
		System.out.println("原来："+Base64.getEncoder().encodeToString(old));
		byte[] key=GeneralIv("sanbian");
		//byte[] key=GeneralKey("sanbian");
		byte[] iv= GeneralIv("majing");
		byte[] enc=encrypt(old, key, iv);
		System.out.println("加密："+enc);
		byte[] dec=decrypt(enc, key, iv);
		System.out.println("解密："+Base64.getEncoder().encodeToString(dec));
	
	}
	private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding";
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static SecretKeySpec toKey(byte[] key) {
        return new SecretKeySpec(key, KEY_ALGORITHM);
    }

    public static byte[] encrypt(byte[] data, SecretKeySpec key, String cipherAlgorithm, IvParameterSpec spec) {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm, "BC");
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] decrypt(byte[] data, SecretKeySpec key, String cipherAlgorithm, IvParameterSpec spec) {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm, "BC");
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) {
    	SecretKeySpec k = toKey(key);
        return encrypt(data, k, DEFAULT_CIPHER_ALGORITHM, new IvParameterSpec(iv));
    }

    /**
     *  初始向量和密钥相同
     */
    public static byte[] encrypt(byte[] data, byte[] key) {
        return encrypt(data, key, key);
    }

    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) {
    	SecretKeySpec k = toKey(key);
        return decrypt(data, k, DEFAULT_CIPHER_ALGORITHM, new IvParameterSpec(iv));
    }

    /**
     *  初始向量和密钥相同
     */
    public static byte[] decrypt(byte[] data, byte[] key) {
        return decrypt(data, key, key);
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
		System.out.println("密钥："+md.digest());
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
            if (hv.length() < 2) {  
                stringBuilder.append(0);  
            }  
            stringBuilder.append("0x"+hv.toUpperCase()+",");  
        }  
        return stringBuilder.toString();  
    }  
}
