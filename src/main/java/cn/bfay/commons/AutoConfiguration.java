package cn.bfay.commons;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

/**
 * 自动化配置.
 *
 * @author wangjiannan
 */
@Configuration //开启配置
public class AutoConfiguration {
    private static final Logger log = LoggerFactory.getLogger(AutoConfiguration.class);

    //@Bean
    //@ConditionalOnMissingBean//缺失时，初始化bean并添加到SpringIoc
    //public RedisUtils redisUtils() {
    //    log.info(">>>The RedisUtils Not Found，Execute Create New Bean.");
    //    return new RedisUtils();
    //}
    //
    //@Bean
    //@ConditionalOnMissingBean//缺失时，初始化bean并添加到SpringIoc
    //public OkHttpUtils okHttpUtils() {
    //    log.info(">>>The OkHttpUtils Not Found，Execute Create New Bean.");
    //    return new OkHttpUtils();
    //}
    //
    //@Bean
    //@ConditionalOnMissingBean//缺失时，初始化bean并添加到SpringIoc
    //public RedisTime redisTime() {
    //    log.info(">>>The RedisTime Not Found，Execute Create New Bean.");
    //    return new RedisTime();
    //}

}
