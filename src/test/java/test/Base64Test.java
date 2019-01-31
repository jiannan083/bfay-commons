package test;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;

/**
 * Base64Test.
 *
 * @author wangjiannan
 */
public class Base64Test {

    @Test
    public void testSize() {
        String start = "fasdfsdaf";
        String end = Base64.encodeBase64String(start.getBytes());
        int startLength = start.length();
        System.out.println(startLength);
        System.out.println(startLength * 1.333);
        System.out.println(end.length());
        String toStart = StringUtils.newStringUtf8(Base64.decodeBase64(end));
        System.out.println(toStart.length());
        // 转base64编码，变大，原始*1.33，解码还原原来大小
        //9
        //11.997
        //12
        //9
    }

}
