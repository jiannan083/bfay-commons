package test;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.net.URLCodec;
import org.junit.Test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CodecTest.
 *
 * @author wangjiannan
 */
public class CodecTest {

    /**
     * base64.
     */
    @Test
    public void testBase64() {
        System.out.println("==============Base64================");
        byte[] data = "jianggujin".getBytes();
        Base64 base64 = new Base64();
        String encode = base64.encodeAsString(data);
        System.out.println(encode);
        System.out.println(new String(base64.decode(encode)));
    }

    /**
     * md5.
     */
    @Test
    public void testMD5() throws NoSuchAlgorithmException {
        //System.out.println("==============MD5================");
        //String result = DigestUtils.md5Hex("jianggujin");
        //System.out.println(result);
        //
        //MessageDigest md = MessageDigest.getInstance("MD5");  // JDK提供的MD5方法
        //byte[] md5Bytes = md.digest("原文".getBytes());  // 加密字节序列 得到 128个比特的摘要，即16字节
        //System.out.println(Hex.encodeHex(md5Bytes));  // 每4个比特转成一位16进制数
        // Apache common codec 提供的MD5方法，最终调用的还是JDK
        String result = DigestUtils.md5Hex("原文");
        System.out.println("--MD5--" + result);
    }

    /**
     * URLCodec可以对url中的参数进行编码.
     *
     * @throws Exception e
     */
    @Test
    public void testURLCodec() throws Exception {
        System.out.println("==============URLCodec================");
        URLCodec codec = new URLCodec();
        String data = "蒋固金";
        String encode = codec.encode(data, "UTF-8");
        System.out.println(encode);
        System.out.println(codec.decode(encode, "UTF-8"));
    }

    /**
     * SHA-1（160比特）、SHA2（SHA-256、SHA-384、SHA-512）.
     *
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testSha() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");  // JDK提供的SHA方法
        byte[] md5Bytes = md.digest("原文".getBytes());
        System.out.println(Hex.encodeHex(md5Bytes));

        System.out.println(DigestUtils.sha256Hex("原文"));  // Apache common codec 提供的SHA方法，最终调用的还是JDK
    }

    @Test
    public void testCodec() throws Exception {
        // 摘要 MD5 应用：用户密码加密
        System.out.println("--MD5--" + DigestUtils.md5Hex("原文"));

        // 摘要 SHA SHA-1（160比特）、SHA2（SHA-256、SHA-384、SHA-512 应用：数字签名
        System.out.println("--SHA-256--" + DigestUtils.sha256Hex("原文"));
        System.out.println("--SHA-384--" + DigestUtils.sha384Hex("原文"));
        System.out.println("--SHA-512--" + DigestUtils.sha512Hex("原文"));

        // 带有密钥的摘要 Hmac 应用：会话认证MAC
        SecretKey sk = KeyGenerator.getInstance("HmacMD5").generateKey();  // 得到密钥
        SecretKey rsk = new SecretKeySpec(sk.getEncoded(), "HmacMD5"); // 格式化密钥
        Mac mac = Mac.getInstance("HmacMD5");   // 确定算法
        mac.init(rsk);  // 确定密钥
        byte[] digest = mac.doFinal("原文".getBytes());  // 加密
        System.out.println("--Hmac--" + Hex.encodeHexString(digest));

        // 对称密码 之 Base64编码 每6比特转成一位64进制数
        // 应用：字节数组对应的字符串是乱码时，可以进行Base64编码，使得能显示成简单的字符串
        byte[] base64Encode = Base64.encodeBase64("原文".getBytes());
        System.out.println("--base64 编码--" + Hex.encodeHexString(base64Encode));
        System.out.println("--base64 解码--" + new String(Base64.decodeBase64(base64Encode)));

        // 对称密码之 AES
        KeyGenerator kg = KeyGenerator.getInstance("AES"); // 生成key
        kg.init(128);  // 确定密钥长度
        byte[] keyBytes = kg.generateKey().getEncoded();
        Key key = new SecretKeySpec(keyBytes, "AES"); // 格式化key
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // 确定算法
        cipher.init(Cipher.ENCRYPT_MODE, key);    // 确定密钥
        byte[] result = cipher.doFinal("原文".getBytes());  // 加密
        System.out.println("--aes 编码--" + Base64.encodeBase64String(result));  // 不进行Base64编码的话，那么这个字节数组对应的字符串就是乱码
        cipher.init(Cipher.DECRYPT_MODE, key); // 进入解密模式
        System.out.println("--aes 解码--" + new String(cipher.doFinal(result))); // 解密

        // 对称密码之 基于口令的密码PBE
        String pwd = "hogen";     // 口令
        PBEKeySpec keySpec = new PBEKeySpec(pwd.toCharArray());  // 密钥格式化
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");  // 密钥工厂
        Key key1 = factory.generateSecret(keySpec);
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(8);  // 盐
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 100);  // PBE参数格式化
        Cipher cipher1 = Cipher.getInstance("PBEWithMD5AndDES");  // 确定算法
        cipher1.init(Cipher.ENCRYPT_MODE, key1, parameterSpec); // 确定口令 和 盐
        byte[] result1 = cipher1.doFinal("原文".getBytes()); // 加密
        System.out.println("--编码--" + Base64.encodeBase64String(result1));
        cipher1.init(Cipher.DECRYPT_MODE, key1, parameterSpec); // 进入解密模式
        System.out.println("--解码--" + new String(cipher1.doFinal(result1))); // 解密

        // 非对称加密 RSA 私钥加密，公钥解密
        // 生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
        // 格式化私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        Cipher cipher2 = Cipher.getInstance("RSA");  // 确定算法
        cipher2.init(Cipher.ENCRYPT_MODE, privateKey);  // 确定加密密钥
        byte[] result2 = cipher2.doFinal("原文".getBytes());  // 加密
        System.out.println("--rsa 编码--" + Base64.encodeBase64String(result2));
        // 格式化公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        cipher2 = Cipher.getInstance("RSA"); // 确定算法
        cipher2.init(Cipher.DECRYPT_MODE, publicKey);  // 确定公钥
        System.out.println("--rsa 解码--" + new String(cipher2.doFinal(result2))); // 解密
    }
}
