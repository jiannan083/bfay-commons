package cn.bfay.commons.redis;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.BoundValueOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

/**
 * redis工具类.
 *
 * @author wangjiannan
 */
@Component
public class RedisUtils {
    private static final Logger logger = LoggerFactory.getLogger(RedisUtils.class);

    private static RedisConnectionFactory factory;
    private static RedisTemplate<String, Object> template;
    private static StringRedisTemplate stringRedisTemplate;
    private static ObjectMapper mapper = new ObjectMapper();

    public RedisUtils() {
    }

    @Autowired
    public void setFactory(RedisConnectionFactory factory) {
        RedisUtils.factory = factory;
    }

    @PostConstruct
    public static void init() {
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        //mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.registerModule(new JavaTimeModule());
        mapper.setTimeZone(TimeZone.getTimeZone("GMT+8"));

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(RedisUtils.factory);
        GenericJackson2JsonRedisSerializer serializer = new GenericJackson2JsonRedisSerializer(mapper);
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(serializer);
        template.setHashValueSerializer(serializer);
        template.afterPropertiesSet();
        RedisUtils.template = template;
    }

    @Autowired
    public void setStringRedisTemplate(StringRedisTemplate stringRedisTemplate) {
        RedisUtils.stringRedisTemplate = stringRedisTemplate;
    }

    /**
     * 设置键为key的值.
     *
     * @param key   键
     * @param value 值
     */
    public static void setValue(String key, Object value) {
        template.opsForValue().set(key, value);
    }

    /**
     * 设置String类型的值.
     *
     * @param key   键
     * @param value String类型的值
     */
    public static void setValue(String key, String value) {
        stringRedisTemplate.opsForValue().set(key, value);
    }

    /**
     * 设置值,带过期时间.
     *
     * @param key    键
     * @param value  值
     * @param expire 有效时间,单位:秒
     */
    public static void setValue(String key, Object value, long expire) {
        template.opsForValue().set(key, value, expire, TimeUnit.SECONDS);
    }

    /**
     * 设置String类型的值,带过期时间.
     *
     * @param key    键
     * @param value  String类型的值
     * @param expire 过期时间,单位:秒
     */
    public static void setValue(String key, String value, long expire) {
        stringRedisTemplate.opsForValue().set(key, value, expire, TimeUnit.SECONDS);
    }

    /**
     * 向键为key的hashmap中添加值.
     *
     * @param key   键
     * @param field 字段
     * @param value 值
     */
    public static void putValue(String key, String field, Object value) {
        template.boundHashOps(key).put(field, value);
    }

    /**
     * 向键为key的hashmap中添加值.
     *
     * @param key    键
     * @param field  字段
     * @param value  值
     * @param expire 有效时间,单位:秒
     */
    public static void putValue(String key, String field, Object value, long expire) {
        BoundHashOperations<String, Object, Object> ops = template.boundHashOps(key);
        ops.put(field, value);
        ops.expire(expire, TimeUnit.SECONDS);
    }

    /**
     * 向键为key的hashmap中添加值.
     *
     * @param key   键
     * @param field 字段
     * @param value 值
     * @param date  有效时间
     */
    public static void putValue(String key, String field, Object value, Date date) {
        BoundHashOperations<String, Object, Object> ops = template.boundHashOps(key);
        ops.put(field, value);
        ops.expireAt(date);
    }

    /**
     * 设置键值为key的map.
     *
     * @param key 键
     * @param map map对象实例
     */
    public static void setMap(String key, Map<Object, Object> map) {
        template.boundHashOps(key).putAll(map);
    }

    /**
     * 设置键值为key的map。有过期时间.
     *
     * @param key    键
     * @param map    map
     * @param expire 过期时间,单位:秒
     */
    public static void setMap(String key, Map<? extends Object, ? extends Object> map, long expire) {
        BoundHashOperations<String, Object, Object> ops = template.boundHashOps(key);
        ops.putAll(map);
        ops.expire(expire, TimeUnit.SECONDS);
    }

    /**
     * 设置键值为key的map。有过期时间.
     *
     * @param key  键
     * @param map  map
     * @param date 有效时间
     */
    public static void setMap(String key, Map<? extends Object, ? extends Object> map, Date date) {
        BoundHashOperations<String, Object, Object> ops = template.boundHashOps(key);
        ops.putAll(map);
        ops.expireAt(date);
    }

    /**
     * 获取键为key的map.
     *
     * @param key 键
     * @return 返回map
     */
    public static Map<Object, Object> getMap(String key) {
        return template.opsForHash().entries(key);
    }

    /**
     * 获取键为key的map.
     *
     * @param key   键
     * @param clazz 需要转换成的类型
     * @param <T>   类型
     * @return 返回map
     */
    public static <T> Map<String, T> getMap(String key, Class<T> clazz) {

        Map<String, T> resultMap = new HashMap<>();
        getMap(key).forEach((key1, value) -> {
            try {
                resultMap.put((String) key1, mapper.readValue(mapper.writeValueAsString(value), clazz));
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
            }
        });
        return resultMap;
    }

    /**
     * 获取键为key的map.
     *
     * @param key  键
     * @param type 需要转换成的类型
     * @param <T>  类型
     * @return 返回map
     */
    public static <T> Map<String, T> getMap(String key, TypeReference type) {

        Map<String, T> resultMap = new HashMap<>();
        getMap(key).forEach((key1, value) -> {
            try {
                resultMap.put((String) key1, mapper.readValue(mapper.writeValueAsString(value), type));
            } catch (IOException e) {
                logger.error(e.getMessage(), e);
            }
        });
        return resultMap;
    }

    /**
     * 批量获取值.
     *
     * @param keys 键列表
     * @return 值列表
     */
    public static List<String> multiGet(List<String> keys) {
        return stringRedisTemplate.opsForValue().multiGet(keys);
    }

    /**
     * 获取键为key的map中的指定字段名的值.
     *
     * @param key   键
     * @param field 字段名称
     * @return 返回值
     */
    public static Object getValue(String key, String field) {
        return stringRedisTemplate.boundHashOps(key).get(field);
    }

    /**
     * 获取键为key的map中的指定字段名的值.
     *
     * @param key   键
     * @param field 字段
     * @param clazz 需要转换成的类型
     * @param <T>   类型
     * @return 返回转换后的类型
     */
    public static <T> T getValue(String key, String field, Class<T> clazz) {
        Object originValue = getValue(key, field);
        if (originValue == null) {
            return null;
        }
        try {
            return mapper.readValue(String.valueOf(originValue), clazz);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * 获取键为key的map中的指定字段名的值.
     *
     * @param key   键
     * @param field 字段
     * @param type  需要转换成的类型
     * @param <T>   类型
     * @return 返回转换后的类型
     */
    public static <T> T getValue(String key, String field, TypeReference type) {
        Object originValue = getValue(key, field);
        if (originValue == null) {
            return null;
        }
        try {
            return mapper.readValue(String.valueOf(originValue), type);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * 获取键为key的值.
     *
     * @param key 键
     * @return 返回String
     */
    public static String getValue(String key) {
        return stringRedisTemplate.opsForValue().get(key);
    }


    /**
     * 获取键为key的值.
     *
     * @param key   键
     * @param clazz 需要转换成的类型
     * @param <T>   类型
     * @return 返回转换后的类型
     */
    public static <T> T getValue(String key, Class<T> clazz) {
        String originValue = getValue(key);
        if (originValue == null) {
            return null;
        }
        try {
            return mapper.readValue(originValue, clazz);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * 获取键为key的值.
     *
     * @param key  键
     * @param type 需要转换成的类型
     * @param <T>  类型
     * @return 返回转换后的类型
     */
    public static <T> T getValue(String key, TypeReference type) {
        String originValue = getValue(key);
        if (originValue == null) {
            return null;
        }
        try {
            return mapper.readValue(originValue, type);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * 查询redis里是否有对应的key.
     *
     * @param key 要查询的key
     * @return true:有, false:无
     */
    public static Boolean hasKey(String key) {
        return template.hasKey(key);
    }


    /**
     * 删除键值.
     *
     * @param key 键
     */
    public static void delete(String key) {
        template.delete(key);
    }

    /**
     * 删除哈希表子键值.
     *
     * @param key   键
     * @param field 字段名称
     */
    public static void delete(String key, String field) {
        if (template.opsForHash().hasKey(key, field)) {
            template.opsForHash().delete(key, field);
        }
    }

    public static Integer getInteger(String key) {
        return (Integer) template.boundValueOps(key).get();
    }

    /**
     * set int value.
     */
    public static void setInteger(String key, Integer value, long expire) {
        BoundValueOperations<String, Object> ops = template.boundValueOps(key);
        ops.set(value);
        ops.expire(expire, TimeUnit.SECONDS);
    }

    public static void setInteger(String key, Integer value) {
        template.boundValueOps(key).set(value);
    }

    public static long increment(String key, Long delta) {
        return template.boundValueOps(key).increment(delta);
    }


    public static List<String> keys(String prefix) {
        Set<String> result = stringRedisTemplate.keys(prefix + "*");
        return new ArrayList<>(result);
    }

    /**
     * 延长缓存时间.
     *
     * @param key     键值
     * @param timeout 时间长度
     * @param unit    时间单位
     * @return 操作结果
     */
    public static boolean expire(String key, long timeout, TimeUnit unit) {
        return template.expire(key, timeout, unit);
    }

    /**
     * 缓存剩余时间.
     *
     * @param key 键值
     * @return 秒
     */
    public static long getExpireTime(String key) {
        return template.getExpire(key, TimeUnit.SECONDS);
    }

}
