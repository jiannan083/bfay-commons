package cn.bfay.commons.util;

import com.google.common.collect.Maps;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密工具类-EncryptionUtils.
 * Base64:对称密码,每6比特转成一位64进制数,应用：字节数组对应的字符串是乱码时，可以进行Base64编码，使得能显示成简单的字符串.
 * md5单向加密算法:应用:用户密码加密.
 * SHA单向加密算法:SHA-1（160比特）、SHA2（SHA-256、SHA-384、SHA-512 应用:数字签名.
 * Hmac单向加密算法:有密钥,全称为“Hash Message Authentication Code”,中文名“散列消息鉴别码”,算法可选以下多种算法:
 * HmacMD5
 * HmacSHA1
 * HmacSHA256
 * HmacSHA384
 * HmacSHA512
 * 应用：会话认证MAC.
 *
 * @author wangjiannan
 */
public class EncryptionUtils {
    private static final Logger log = LoggerFactory.getLogger(EncryptionUtils.class);

    private static final String CONVERSION_TYPE_BASE64 = "base64";
    private static final String CONVERSION_TYPE_HEX = "hex";

    private static final String ALGORITHM_HMAC_MD5 = "HmacMD5";
    private static final String ALGORITHM_HMAC_SHA1 = "HmacSHA1";
    private static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";
    private static final String ALGORITHM_HMAC_SHA384 = "HmacSHA384";
    private static final String ALGORITHM_HMAC_SHA512 = "HmacSHA512";

    // 算法 DES  3DES  AES
    private static final String ALGORITHM_DES = "DES";
    private static final String ALGORITHM_3DES = "DESede";
    private static final String ALGORITHM_AES = "AES";
    private static final String ALGORITHM_RSA = "RSA";
    // 工作模式 ECB  CBC
    private static final String WORK_MODE_ECB = "ECB";
    private static final String WORK_MODE_CBC = "CBC";
    // 填充模式 NoPadding  PKCS5Padding  PKCS7Padding
    private static final String PADDING_MODE_NO = "NoPadding";
    private static final String PADDING_MODE_PKCS5 = "PKCS5Padding";
    private static final String PADDING_MODE_PKCS7 = "PKCS7Padding";

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";

    // 私钥加密，公钥解密
    private static final String RSA_MODE_PRIEN = "PRIEN";
    // 公钥加密，私钥解密
    private static final String RSA_MODE_PUBEN = "PUBEN";

    // 签名算法
    private static final String SIGN_ALGORITHM_MD2WITHRSA = "MD2withRSA";
    private static final String SIGN_ALGORITHM_MD5WITHRSA = "MD5withRSA";
    private static final String SIGN_ALGORITHM_SHA1WITHRSA = "SHA1withRSA";
    private static final String SIGN_ALGORITHM_SHA224WITHRSA = "SHA224withRSA";
    private static final String SIGN_ALGORITHM_SHA256WITHRSA = "SHA256withRSA";
    private static final String SIGN_ALGORITHM_SHA384WITHRSA = "SHA384withRSA";
    private static final String SIGN_ALGORITHM_SHA512WITHRSA = "SHA512withRSA";
    private static final String SIGN_ALGORITHM_RIPEMD128WITHRSA = "RIPEMD128withRSA";
    private static final String SIGN_ALGORITHM_RIPEMD160WITHRSA = "RIPEMD160withRSA";

    // BouncyCastle是一个开源的加解密解决方案，主页在http://www.bouncycastle.org/
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //public static String generateKeyWithDes() {
    //    return generateKey(ALGORITHM_DES, 56);
    //}
    //
    //public static String generateKeyWith3Des() {
    //    return generateKey(ALGORITHM_3DES, 112);
    //}
    //
    //public static String generateKeyWithAes() {
    //    return generateKey(ALGORITHM_AES, 128);
    //}
    //
    //private static String generateKey(String algorithm, int length) {
    //    try {
    //        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);//密钥生成器
    //        keyGenerator.init(length);//指定密钥长度
    //        SecretKey secretKey = keyGenerator.generateKey();//用密钥生成器生成密钥
    //        byte[] keyBytes = secretKey.getEncoded();//得到密钥的byte数组
    //        return StringUtils.newStringUtf8(keyBytes);
    //    } catch (Exception e) {
    //        log.error("生成key失败", e);
    //        return "";
    //    }
    //}

    /**
     * 生成rsa密钥,默认512.
     *
     * @return map-publicKey;privateKey
     */
    public static Map<String, String> generateKeyWithRsa() {
        return generateKeyWithRsa(512);
    }

    /**
     * 生成rsa密钥.
     *
     * @param keyLength 密钥长度为64的整数倍，最大是65536
     * @return map-publicKey;privateKey
     */
    public static Map<String, String> generateKeyWithRsa(int keyLength) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);//密钥长度为64的整数倍，最大是65536
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            Map<String, String> result = Maps.newHashMap();
            result.put("publicKey", Base64.encodeBase64String(rsaPublicKey.getEncoded()));
            result.put("privateKey", Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
            return result;
        } catch (Exception e) {
            log.error("生成key失败", e);
            return null;
        }
    }

    // ----- encode start -----

    /**
     * Base64编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithBase64(String content) {
        return Base64.encodeBase64String(StringUtils.getBytesUtf8(content));
    }

    /**
     * md5编码.
     *
     * @param content 内容/内容+盐/盐+内容
     * @return string
     */
    public static String encodeWithMd5(String content) {
        return Base64.encodeBase64String(DigestUtils.md5(content));
    }

    /**
     * md5编码.
     *
     * @param content 内容/内容+盐/盐+内容
     * @return string
     */
    public static String encodeWithMd5Hex(String content) {
        return DigestUtils.md5Hex(content);
    }

    /**
     * sha256编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha256(String content) {
        return Base64.encodeBase64String(DigestUtils.sha256(content));
    }

    /**
     * sha256编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha256Hex(String content) {
        return DigestUtils.sha256Hex(content);
    }

    /**
     * sha384编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha384(String content) {
        return Base64.encodeBase64String(DigestUtils.sha384(content));
    }

    /**
     * sha384编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha384Hex(String content) {
        return DigestUtils.sha384Hex(content);
    }

    /**
     * sha512编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha512(String content) {
        return Base64.encodeBase64String(DigestUtils.sha512(content));
    }

    /**
     * sha512编码.
     *
     * @param content 内容
     * @return string
     */
    public static String encodeWithSha512Hex(String content) {
        return DigestUtils.sha512Hex(content);
    }

    /**
     * hmacmd5编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacMd5(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_MD5, key, content, CONVERSION_TYPE_BASE64);
    }

    /**
     * hmacmd5编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacMd5Hex(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_MD5, key, content, CONVERSION_TYPE_HEX);
    }

    /**
     * hmacsha1编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha1(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA1, key, content, CONVERSION_TYPE_BASE64);
    }

    /**
     * hmacsha1编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha1Hex(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA1, key, content, CONVERSION_TYPE_HEX);
    }

    /**
     * hmacsha256编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha256(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA256, key, content, CONVERSION_TYPE_BASE64);
    }

    /**
     * hmacsha256编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha256Hex(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA256, key, content, CONVERSION_TYPE_HEX);
    }

    /**
     * hmacsha384编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha384(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA384, key, content, CONVERSION_TYPE_BASE64);
    }

    /**
     * hmacsha384编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha384Hex(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA384, key, content, CONVERSION_TYPE_HEX);
    }

    /**
     * hmacsha512编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha512(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA512, key, content, CONVERSION_TYPE_BASE64);
    }

    /**
     * hmacsha512编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithHmacSha512Hex(String key, String content) {
        return encodeWithHmac(ALGORITHM_HMAC_SHA512, key, content, CONVERSION_TYPE_HEX);
    }

    /**
     * desEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * desEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * desCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * desCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * desEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * desEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * desCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * desCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithDesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * 3desEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * 3desEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * 3desCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * 3desCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * 3desEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * 3desEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * 3desCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * 3desCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWith3DesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * aesEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * aesEcbPkcs5padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * aesCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * aesCbcPkcs5padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS5, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * aesEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * aesEcbPkcs7padding编码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * aesCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * aesCbcPkcs7padding编码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String encodeWithAesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS7, ENCRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * rsa编码-私钥加密，公钥解密.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String encodeWithRsaPriEn(String rsaPrivateKey, String content) {
        return rsa(ENCRYPT, RSA_MODE_PRIEN, null, rsaPrivateKey, content);
    }

    /**
     * rsa编码-公钥加密，私钥解密.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @return string
     */
    public static String encodeWithRsaPubEn(String rsaPublicKey, String content) {
        return rsa(ENCRYPT, RSA_MODE_PUBEN, rsaPublicKey, null, content);
    }

    // ----- encode end -----

    // ----- decode start -----

    /**
     * Base64解码.
     *
     * @param content 内容
     * @return string
     */
    public static String decodeWithBase64(String content) {
        return StringUtils.newStringUtf8(Base64.decodeBase64(content));
    }

    /**
     * desEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * desEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * desCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * desCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * desEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * desEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * desCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * desCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithDesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * 3desEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * 3desEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * 3desCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * 3desCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * 3desEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * 3desEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * 3desCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * 3desCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWith3DesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_3DES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * aesEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesEcbPkcs5padding(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * aesEcbPkcs5padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesEcbPkcs5paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * aesCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesCbcPkcs5padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * aesCbcPkcs5padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesCbcPkcs5paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS5, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * aesEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesEcbPkcs7padding(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, null,
            key, content);
    }

    /**
     * aesEcbPkcs7padding解码.
     *
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesEcbPkcs7paddingHex(String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_ECB, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, null,
            key, content);
    }

    /**
     * aesCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesCbcPkcs7padding(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_BASE64, iv,
            key, content);
    }

    /**
     * aesCbcPkcs7padding解码.
     *
     * @param iv      向量
     * @param key     密钥
     * @param content 内容
     * @return string
     */
    public static String decodeWithAesCbcPkcs7paddingHex(String iv, String key, String content) {
        return desDesedeAes(ALGORITHM_AES, WORK_MODE_CBC, PADDING_MODE_PKCS7, DECRYPT, CONVERSION_TYPE_HEX, iv,
            key, content);
    }

    /**
     * rsa解码-私钥加密，公钥解密.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @return string
     */
    public static String decodeWithRsaPriEn(String rsaPublicKey, String content) {
        return rsa(DECRYPT, RSA_MODE_PRIEN, rsaPublicKey, null, content);
    }

    /**
     * rsa解码-公钥加密，私钥解密.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String decodeWithRsaPubEn(String rsaPrivateKey, String content) {
        return rsa(DECRYPT, RSA_MODE_PUBEN, null, rsaPrivateKey, content);
    }
    // ----- decode end -----


    // ----- sign start -----

    /**
     * Md2WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithMd2WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_MD2WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Md5WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithMd5WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_MD5WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Sha1WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithSha1WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_SHA1WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Sha224WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithSha224WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_SHA224WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Sha256WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithSha256WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_SHA256WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Sha384WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithSha384WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_SHA384WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Sha512WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithSha512WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_SHA512WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Ripemd128WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithRipemd128WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_RIPEMD128WITHRSA, rsaPrivateKey, content);
    }

    /**
     * Ripemd160WithRsa签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    public static String signWithRipemd160WithRsa(String rsaPrivateKey, String content) {
        return rsaSign(SIGN_ALGORITHM_RIPEMD160WITHRSA, rsaPrivateKey, content);
    }

    // ----- sign end -----


    // ----- verify sign start -----

    /**
     * Md2WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithMd2WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_MD2WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Md5WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithMd5WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_MD5WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Sha1WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithSha1WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_SHA1WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Sha224WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithSha224WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_SHA224WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Sha256WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithSha256WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_SHA256WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Sha384WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithSha384WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_SHA384WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Sha512WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithSha512WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_SHA512WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Ripemd128WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithRipemd128WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_RIPEMD128WITHRSA, rsaPublicKey, content, signResult);
    }

    /**
     * Ripemd160WithRsa验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @param signResult   签名
     */
    public static boolean verifySignWithRipemd160WithRsa(String rsaPublicKey, String content, String signResult) {
        return rsaVerifySign(SIGN_ALGORITHM_RIPEMD160WITHRSA, rsaPublicKey, content, signResult);
    }

    // ----- verify sign end -----


    // hmac
    private static String encodeWithHmac(String algorithm, String key, String content, String conversionType) {
        try {
            Mac mac = Mac.getInstance(algorithm); // 确定算法
            SecretKeySpec secretKey = new SecretKeySpec(StringUtils.getBytesUtf8(key), algorithm);
            mac.init(secretKey);
            byte[] result = mac.doFinal(StringUtils.getBytesUtf8(content));
            return processResult(result, conversionType);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    // des/desede/aes
    private static String desDesedeAes(String algorithm, String workMode, String paddingMode, String type,
                                       String conversionType, String iv, String key, String content) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/" + workMode + "/" + paddingMode); // 确定算法
            SecretKeySpec secretKey = new SecretKeySpec(StringUtils.getBytesUtf8(key), algorithm);
            if (ENCRYPT.equals(type)) {
                if (WORK_MODE_CBC.equals(workMode)) {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(StringUtils.getBytesUtf8(iv)));
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                }
                byte[] result = cipher.doFinal(StringUtils.getBytesUtf8(content));
                return processResult(result, conversionType);
            } else if (DECRYPT.equals(type)) {
                if (WORK_MODE_CBC.equals(workMode)) {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(StringUtils.getBytesUtf8(iv)));
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, secretKey);
                }
                if (CONVERSION_TYPE_BASE64.equals(conversionType)) {
                    return StringUtils.newStringUtf8(cipher.doFinal(Base64.decodeBase64(content)));
                } else if (CONVERSION_TYPE_HEX.equals(conversionType)) {
                    return StringUtils.newStringUtf8(cipher.doFinal(Hex.decodeHex(content)));
                } else {
                    throw new Exception("未知转换类型");
                }
            } else {
                throw new Exception("未知处理类型");
            }
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    private static String processResult(byte[] result, String conversionType) {
        if (CONVERSION_TYPE_BASE64.equals(conversionType)) {
            return Base64.encodeBase64String(result);
        } else if (CONVERSION_TYPE_HEX.equals(conversionType)) {
            return Hex.encodeHexString(result);
        } else {
            return Base64.encodeBase64String(result);
        }
    }

    // rsa
    private static String rsa(String type, String rsaMode, String rsaPublicKey, String rsaPrivateKey, String content) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);
            byte[] result;
            if (ENCRYPT.equals(type)) {
                if (RSA_MODE_PRIEN.equals(rsaMode)) {
                    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(rsaPrivateKey));
                    PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
                    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                } else if (RSA_MODE_PUBEN.equals(rsaMode)) {
                    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(rsaPublicKey));
                    PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
                    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                } else {
                    throw new Exception("未知rsa模式");
                }
                result = cipher.doFinal(StringUtils.getBytesUtf8(content));
                return Base64.encodeBase64String(result);
            } else if (DECRYPT.equals(type)) {
                if (RSA_MODE_PRIEN.equals(rsaMode)) {
                    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(rsaPublicKey));
                    PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
                    cipher.init(Cipher.DECRYPT_MODE, publicKey);
                } else if (RSA_MODE_PUBEN.equals(rsaMode)) {
                    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(rsaPrivateKey));
                    PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                } else {
                    throw new Exception("未知rsa模式");
                }
                result = cipher.doFinal(Base64.decodeBase64(content));
                return StringUtils.newStringUtf8(result);
            } else {
                throw new Exception("未知处理类型");
            }
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    /**
     * rsa签名,私钥签名.
     *
     * @param rsaPrivateKey 私钥
     * @param content       内容
     * @return string
     */
    private static String rsaSign(String signAlgorithm, String rsaPrivateKey, String content) {
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(rsaPrivateKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initSign(privateKey);
            signature.update(StringUtils.getBytesUtf8(content));
            byte[] result = signature.sign();
            return Base64.encodeBase64String(result);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    /**
     * rsa验签,公钥验签.
     *
     * @param rsaPublicKey 公钥
     * @param content      内容
     * @return boolean
     */
    private static boolean rsaVerifySign(String signAlgorithm, String rsaPublicKey, String content, String signResult) {
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(rsaPublicKey));
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initVerify(publicKey);
            signature.update(StringUtils.getBytesUtf8(content));
            return signature.verify(Base64.decodeBase64(signResult));
        } catch (Exception e) {
            log.error("处理失败", e);
            return false;
        }
    }

    public static void main(String[] args) {
        //System.out.println("------------------- key -------------------");
        //System.out.println("--des key--" + generateKeyWithDes());
        //System.out.println("--3des key--" + generateKeyWith3Des());
        //System.out.println("--aes key--" + generateKeyWithAes());

        System.out.println();
        System.out.println("------------------- base64 -------------------");
        String base64Content = "wjn123456";
        String base64Encode = encodeWithBase64(base64Content);
        String base64Decode = decodeWithBase64(base64Encode);
        System.out.println("--base64Encode--" + base64Encode);
        System.out.println("--base64Decode--" + base64Decode);


        String md5Content = "18515816387";
        String md5encode = encodeWithMd5(md5Content);
        System.out.println("--md5encode--" + md5encode);
        String md5encodeHex = encodeWithMd5Hex(md5Content);
        System.out.println("--md5encodeHex--" + md5encodeHex);

        String shaContent = "wjn123456";
        System.out.println("--sha256--" + encodeWithSha256(shaContent));
        System.out.println("--sha256Hex--" + encodeWithSha256Hex(shaContent));
        System.out.println("--sha384--" + encodeWithSha384(shaContent));
        System.out.println("--sha384Hex--" + encodeWithSha384Hex(shaContent));
        System.out.println("--sha512--" + encodeWithSha512(shaContent));
        System.out.println("--sha512Hex--" + encodeWithSha512Hex(shaContent));


        System.out.println("------------------- hmac -------------------");
        String hmacSecret = "casdfadsfadsfsdac4wefas";
        String hmacContent = "wjn123456";
        System.out.println("--hmacmd5--" + encodeWithHmacMd5(hmacSecret, hmacContent));
        System.out.println("--hmacmd5Hex--" + encodeWithHmacMd5Hex(hmacSecret, hmacContent));
        System.out.println("--hmacsha1--" + encodeWithHmacSha1(hmacSecret, hmacContent));
        System.out.println("--hmacsha1Hex--" + encodeWithHmacSha1Hex(hmacSecret, hmacContent));
        System.out.println("--hmacsha256--" + encodeWithHmacSha256(hmacSecret, hmacContent));
        System.out.println("--hmacsha256Hex--" + encodeWithHmacSha256Hex(hmacSecret, hmacContent));
        System.out.println("--hmacsha384--" + encodeWithHmacSha384(hmacSecret, hmacContent));
        System.out.println("--hmacsha384Hex--" + encodeWithHmacSha384Hex(hmacSecret, hmacContent));
        System.out.println("--hmacsha512--" + encodeWithHmacSha512(hmacSecret, hmacContent));
        System.out.println("--hmacsha512Hex--" + encodeWithHmacSha512Hex(hmacSecret, hmacContent));


        System.out.println("------------------- des -------------------");
        String desSecret = "lgk5Uf2d";
        String desContent = "wjn123456哈哈";
        String desIv = "56824568";
        String desEcb5 = encodeWithDesEcbPkcs5padding(desSecret, desContent);
        System.out.println("--desEcb5加密--" + desEcb5);
        System.out.println("--desEcb5解密--" + decodeWithDesEcbPkcs5padding(desSecret, desEcb5));
        String desCbc5 = encodeWithDesCbcPkcs5padding(desIv, desSecret, desContent);
        System.out.println("--desCbc5加密--" + desCbc5);
        System.out.println("--desCbc5解密--" + decodeWithDesCbcPkcs5padding(desIv, desSecret, desCbc5));
        String desEcb5Hex = encodeWithDesEcbPkcs5paddingHex(desSecret, desContent);
        System.out.println("--desEcb5Hex加密--" + desEcb5Hex);
        System.out.println("--desEcb5Hex解密--" + decodeWithDesEcbPkcs5paddingHex(desSecret, desEcb5Hex));
        String desCbc5Hex = encodeWithDesCbcPkcs5paddingHex(desIv, desSecret, desContent);
        System.out.println("--desCbc5Hex加密--" + desCbc5Hex);
        System.out.println("--desCbc5Hex解密--" + decodeWithDesCbcPkcs5paddingHex(desIv, desSecret, desCbc5Hex));
        String desEcb7 = encodeWithDesEcbPkcs7padding(desSecret, desContent);
        System.out.println("--desEcb7加密--" + desEcb7);
        System.out.println("--desEcb7解密--" + decodeWithDesEcbPkcs7padding(desSecret, desEcb7));
        String desCbc7 = encodeWithDesCbcPkcs7padding(desIv, desSecret, desContent);
        System.out.println("--desCbc7加密--" + desCbc7);
        System.out.println("--desCbc7解密--" + decodeWithDesCbcPkcs7padding(desIv, desSecret, desCbc7));
        String desEcb7Hex = encodeWithDesEcbPkcs7paddingHex(desSecret, desContent);
        System.out.println("--desEcb7Hex加密--" + desEcb7Hex);
        System.out.println("--desEcb7Hex解密--" + decodeWithDesEcbPkcs7paddingHex(desSecret, desEcb7Hex));
        String desCbc7Hex = encodeWithDesCbcPkcs7paddingHex(desIv, desSecret, desContent);
        System.out.println("--desCbc7Hex加密--" + desCbc7Hex);
        System.out.println("--desCbc7Hex解密--" + decodeWithDesCbcPkcs7paddingHex(desIv, desSecret, desCbc7Hex));


        System.out.println("------------------- 3des -------------------");
        String tdesSecret = "lgk5Uf2dtf4rdg65";
        String tdesContent = "wjn123456哈哈";
        String tdesIv = "56824568";
        String tdesEcb5 = encodeWith3DesEcbPkcs5padding(tdesSecret, tdesContent);
        System.out.println("--3desEcb5加密--" + tdesEcb5);
        System.out.println("--3desEcb5解密--" + decodeWith3DesEcbPkcs5padding(tdesSecret, tdesEcb5));
        String tdesCbc5 = encodeWith3DesCbcPkcs5padding(tdesIv, tdesSecret, tdesContent);
        System.out.println("--3desCbc5加密--" + tdesCbc5);
        System.out.println("--3desCbc5解密--" + decodeWith3DesCbcPkcs5padding(tdesIv, tdesSecret, tdesCbc5));
        String tdesEcb5Hex = encodeWith3DesEcbPkcs5paddingHex(tdesSecret, tdesContent);
        System.out.println("--3desEcb5Hex加密--" + tdesEcb5Hex);
        System.out.println("--3desEcb5Hex解密--" + decodeWith3DesEcbPkcs5paddingHex(tdesSecret, tdesEcb5Hex));
        String tdesCbc5Hex = encodeWith3DesCbcPkcs5paddingHex(tdesIv, tdesSecret, tdesContent);
        System.out.println("--3desCbc5Hex加密--" + tdesCbc5Hex);
        System.out.println("--3desCbc5Hex解密--" + decodeWith3DesCbcPkcs5paddingHex(tdesIv, tdesSecret, tdesCbc5Hex));
        String tdesEcb7 = encodeWith3DesEcbPkcs7padding(tdesSecret, tdesContent);
        System.out.println("--3desEcb7加密--" + tdesEcb7);
        System.out.println("--3desEcb7解密--" + decodeWith3DesEcbPkcs7padding(tdesSecret, tdesEcb7));
        String tdesCbc7 = encodeWith3DesCbcPkcs7padding(tdesIv, tdesSecret, tdesContent);
        System.out.println("--3desCbc7加密--" + tdesCbc7);
        System.out.println("--3desCbc7解密--" + decodeWith3DesCbcPkcs7padding(tdesIv, tdesSecret, tdesCbc7));
        String tdesEcb7Hex = encodeWith3DesEcbPkcs7paddingHex(tdesSecret, tdesContent);
        System.out.println("--3desEcb7Hex加密--" + tdesEcb7Hex);
        System.out.println("--3desEcb7Hex解密--" + decodeWith3DesEcbPkcs7paddingHex(tdesSecret, tdesEcb7Hex));
        String tdesCbc7Hex = encodeWith3DesCbcPkcs7paddingHex(tdesIv, tdesSecret, tdesContent);
        System.out.println("--3desCbc7Hex加密--" + tdesCbc7Hex);
        System.out.println("--3desCbc7Hex解密--" + decodeWith3DesCbcPkcs7paddingHex(tdesIv, tdesSecret, tdesCbc7Hex));


        System.out.println("------------------- aes -------------------");
        String aesSecret = "denh4ddjkdn5dsas";
        String aesContent = "wjn123456哈哈";
        String aesIv = "1234567980123456";
        String aesEcb5 = encodeWithAesEcbPkcs5padding(aesSecret, aesContent);
        System.out.println("--aesEcb5加密--" + aesEcb5);
        System.out.println("--aesEcb5解密--" + decodeWithAesEcbPkcs5padding(aesSecret, aesEcb5));
        String aesCbc5 = encodeWithAesCbcPkcs5padding(aesIv, aesSecret, aesContent);
        System.out.println("--aesCbc5加密--" + aesCbc5);
        System.out.println("--aesCbc5解密--" + decodeWithAesCbcPkcs5padding(aesIv, aesSecret, aesCbc5));
        String aesEcb5Hex = encodeWithAesEcbPkcs5paddingHex(aesSecret, aesContent);
        System.out.println("--aesEcb5Hex加密--" + aesEcb5Hex);
        System.out.println("--aesEcb5Hex解密--" + decodeWithAesEcbPkcs5paddingHex(aesSecret, aesEcb5Hex));
        String aesCbc5Hex = encodeWithAesCbcPkcs5paddingHex(aesIv, aesSecret, aesContent);
        System.out.println("--aesCbc5Hex加密--" + aesCbc5Hex);
        System.out.println("--aesCbc5Hex解密--" + decodeWithAesCbcPkcs5paddingHex(aesIv, aesSecret, aesCbc5Hex));
        String aesEcb7 = encodeWithAesEcbPkcs7padding(aesSecret, aesContent);
        System.out.println("--aesEcb7加密--" + aesEcb7);
        System.out.println("--aesEcb7解密--" + decodeWithAesEcbPkcs7padding(aesSecret, aesEcb7));
        String aesCbc7 = encodeWithAesCbcPkcs7padding(aesIv, aesSecret, aesContent);
        System.out.println("--aesCbc7加密--" + aesCbc7);
        System.out.println("--aesCbc7解密--" + decodeWithAesCbcPkcs7padding(aesIv, aesSecret, aesCbc7));
        String aesEcb7Hex = encodeWithAesEcbPkcs7paddingHex(aesSecret, aesContent);
        System.out.println("--aesEcb7Hex加密--" + aesEcb7Hex);
        System.out.println("--aesEcb7Hex解密--" + decodeWithAesEcbPkcs7paddingHex(aesSecret, aesEcb7Hex));
        String aesCbc7Hex = encodeWithAesCbcPkcs7paddingHex(aesIv, aesSecret, aesContent);
        System.out.println("--aesCbc7Hex加密--" + aesCbc7Hex);
        System.out.println("--aesCbc7Hex解密--" + decodeWithAesCbcPkcs7paddingHex(aesIv, aesSecret, aesCbc7Hex));

        System.out.println();

        System.out.println("------------------- rsa -------------------");
        //Map<String, String> rsaKeys = generateKeyWithRsa();
        //rsaKeys.forEach((key, value) -> System.out.println(key + "=" + value));
        String privateKey = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAgHokQbkMbDwJ8iiZjRyxBbposw1hMd41XO5aeqt2aeazHoLkXmHgyEA2ZiVbf6aICRr/blIYYkDXJ/T4DeZIUwIDAQABAkAZp0niDa8bVYmu3sh6UsZOHICXcA5+RJ5nJfjPEbmdP3jOCDaEh5EnLfMEqdI0nMvnX8zWOa8GJ8Y/UCI2X0wBAiEAxMS+m9uXw7msinCLBojVEfRQsBsM34YY+UWLhx5xWVMCIQCnJsQTrTNALWLqyI17TIXwOoNo6bzsLTVvfUOnqZZ1AQIhAIq88mywg6yUgUzHl68O0bUsH6xcFlKQmZFA8OVfmKpTAiBxwm1yIs+dnwYSWloID2WcwIYNEf81EfOrJCq2YjH3AQIgYA3iYwv2dgr7uGNQyhOugpE7NP6Be0pOHFXK2xb5nGI=";
        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIB6JEG5DGw8CfIomY0csQW6aLMNYTHeNVzuWnqrdmnmsx6C5F5h4MhANmYlW3+miAka/25SGGJA1yf0+A3mSFMCAwEAAQ==";
        String rsaContent = "我是fds245哈5哈d";
        String rsaPriEn = encodeWithRsaPriEn(privateKey, rsaContent);
        System.out.println("--rsa-pri-en加密--" + rsaPriEn);
        System.out.println("--rsa-pri-en解密--" + decodeWithRsaPriEn(publicKey, rsaPriEn));
        String rsaPubEn = encodeWithRsaPubEn(publicKey, rsaContent);
        System.out.println("--rsa-pub-en加密--" + rsaPubEn);
        System.out.println("--rsa-pub-en解密--" + decodeWithRsaPubEn(privateKey, rsaPubEn));

        System.out.println();

        System.out.println("------------------- sign -------------------");
        String md2Sign = signWithMd2WithRsa(privateKey, rsaContent);
        System.out.println("--md2签名--" + md2Sign);
        System.out.println("--md2验签--" + verifySignWithMd2WithRsa(publicKey, rsaContent, md2Sign));
        String md5Sign = signWithMd5WithRsa(privateKey, rsaContent);
        System.out.println("--md5签名--" + md5Sign);
        System.out.println("--md5验签--" + verifySignWithMd5WithRsa(publicKey, rsaContent, md5Sign));
        String sha1Sign = signWithSha1WithRsa(privateKey, rsaContent);
        System.out.println("--sha1签名--" + sha1Sign);
        System.out.println("--sha1验签--" + verifySignWithSha1WithRsa(publicKey, rsaContent, sha1Sign));
        String sha224Sign = signWithSha224WithRsa(privateKey, rsaContent);
        System.out.println("--sha224签名--" + sha224Sign);
        System.out.println("--sha224验签--" + verifySignWithSha224WithRsa(publicKey, rsaContent, sha224Sign));
        String sha256Sign = signWithSha256WithRsa(privateKey, rsaContent);
        System.out.println("--sha256签名--" + sha256Sign);
        System.out.println("--sha256验签--" + verifySignWithSha256WithRsa(publicKey, rsaContent, sha256Sign));
        //String sha384Sign = signWithSha384WithRsa(privateKey, rsaContent);
        //System.out.println("--sha384签名--" + sha384Sign);
        //System.out.println("--sha384验签--" + verifySignWithSha384WithRsa(publicKey, rsaContent, sha384Sign));
        //String sha512Sign = signWithSha512WithRsa(privateKey, rsaContent);
        //System.out.println("--sha512签名--" + sha512Sign);
        //System.out.println("--sha512验签--" + verifySignWithSha512WithRsa(publicKey, rsaContent, sha512Sign));
        String ripemd128Sign = signWithRipemd128WithRsa(privateKey, rsaContent);
        System.out.println("--ripemd128签名--" + ripemd128Sign);
        System.out.println("--ripemd128验签--" + verifySignWithRipemd128WithRsa(publicKey, rsaContent, ripemd128Sign));
        String ripemd160Sign = signWithRipemd160WithRsa(privateKey, rsaContent);
        System.out.println("--ripemd160签名--" + ripemd160Sign);
        System.out.println("--ripemd160验签--" + verifySignWithRipemd160WithRsa(publicKey, rsaContent, ripemd160Sign));

    }
}
