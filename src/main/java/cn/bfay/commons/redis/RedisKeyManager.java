package cn.bfay.commons.redis;

/**
 * RedisKeyManager.
 *
 * @author wangjiannan
 */
public class RedisKeyManager {

    public static String generateGoodsInfoKey(String skuid) {
        return String.format("bfay:goodsinfo:%s", skuid);
    }
}
