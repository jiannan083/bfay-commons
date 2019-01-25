package cn.bfay.commons.util;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

/**
 * DateUtils.
 *
 * @author wangjiannan
 */
public class DateUtils {
    private static final String PATTERN_DEFAULT = "yyyy-MM-dd HH:mm:ss";
    private static final String PATTERN_SHORT_TIME = "yyyy-MM-dd";
    private static final String PATTERN_INIT_DATE = "yyyyMMdd";
    private static final String PATTERN_HHMMSS = "HHmmss";

    /**
     * 一天包含的毫秒数.
     */
    private static final long ONE_DAY_TIME_MS = 24 * 60 * 60 * 1000L;
    private static final long SECONDS_PRE_DAY = 24L * 60 * 60;

    /**
     * format date to "yyyy-MM-dd".
     *
     * @param dateTime {@link LocalDateTime}
     * @return string value with format "yyyy-MM-dd"
     */
    public static String toShortTime(LocalDateTime dateTime) {
        return dateTime.format(DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME));
    }

    /**
     * format date to "yyyy-MM-dd".
     *
     * @param date {@link LocalDate}
     * @return string value with format "yyyy-MM-dd"
     */
    public static String toShortTime(LocalDate date) {
        return date.format(DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME));
    }

    /**
     * format int type date "yyyyMMdd" to "yyyy-MM-dd".
     *
     * @param initDate int type of date "yyyyMMdd"
     * @return string value with format "yyyy-MM-dd"
     */
    public static String toShortTime(int initDate) {
        return toShortTime(String.valueOf(initDate));
    }

    /**
     * 日期字符串转换.
     * 转换格式: yyyyMMdd --> yyyy-MM-dd
     *
     * @param dateFrom 源日期
     * @return 目标格式日期
     */
    public static String toShortTime(String dateFrom) {
        return dateFrom.replaceAll("(\\d{4})(\\d{2})(\\d{2})", "$1-$2-$3");
    }

    /**
     * parse "yyyy-MM-dd" format string to {@link LocalDateTime}.
     *
     * @param inputDate string of "yyyy-MM-dd"
     * @return {@link LocalDateTime}
     */
    public static LocalDate parseShortTime(String inputDate) {
        return LocalDate.parse(inputDate, DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME));
    }

    /**
     * parse "yyyy-MM-dd" format string to int type date "yyyyMMdd".
     *
     * @param inputDate string of "yyyy-MM-dd"
     * @return int type of date
     */
    public static Integer parseShortTimeInt(String inputDate) {
        return Integer.parseInt(inputDate.replace("-", ""));
    }

    /**
     * format {@link LocalDateTime} to "yyyy-MM-dd HH:mm:ss" string.
     *
     * @param date {@link LocalDateTime}
     * @return string of "yyyy-MM-dd HH:mm:ss"
     */
    public static String toLongTime(LocalDateTime date) {
        return date.format(DateTimeFormatter.ofPattern(PATTERN_DEFAULT));
    }

    /**
     * parse string "yyyy-MM-dd HH:mm:ss" to {@link LocalDateTime}.
     *
     * @param inputDate string of "yyyy-MM-dd HH:mm:ss"
     * @return {@link LocalDateTime}
     */
    public static LocalDateTime parseLongTime(String inputDate) {
        return LocalDateTime.parse(inputDate, DateTimeFormatter.ofPattern(PATTERN_DEFAULT));
    }

    /**
     * 取当前日期.
     * 格式: yyyy-MM-dd
     *
     * @return string of "yyyy-MM-dd"
     */
    public static String shortTimeToday() {
        return LocalDate.now().format(DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME));
    }

    public static int todayInt() {
        return toIntDate(LocalDate.now());
    }

    public static int toIntDate(LocalDateTime bizDate) {
        return Integer.parseInt(bizDate.format(DateTimeFormatter.ofPattern(PATTERN_INIT_DATE)));
    }

    public static int toIntDate(LocalDate bizDate) {
        return Integer.parseInt(bizDate.format(DateTimeFormatter.ofPattern(PATTERN_INIT_DATE)));
    }

    public static LocalDate parseIntDate(int initDate) {
        return LocalDate.parse(String.valueOf(initDate), DateTimeFormatter.ofPattern(PATTERN_INIT_DATE));
    }

    public static String longTimeCurrent() {
        return toLongTime(LocalDateTime.now());
    }

    /**
     * 根据日期取星期.
     *
     * @param dateStr yyyy-MM-dd
     * @return 星期一 ~ 星期日
     */
    public static String weekOfChineseString(String dateStr) {
        return weekOfChineseString(LocalDate.parse(dateStr, DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME)));
    }

    /**
     * 返回中文星期字符串.
     *
     * @param date {@link LocalDate}
     * @return 星期一 ~ 星期日
     */
    public static String weekOfChineseString(LocalDate date) {
        return date.format(DateTimeFormatter.ofPattern("EEEE", Locale.SIMPLIFIED_CHINESE));
    }

    /**
     * 返回中文星期字符串.
     *
     * @param date {@link LocalDateTime}
     * @return 星期一 ~ 星期日
     */
    public static String weekOfChineseString(LocalDateTime date) {
        return date.format(DateTimeFormatter.ofPattern("EEEE", Locale.SIMPLIFIED_CHINESE));
    }

    /**
     * 本周第一天.
     *
     * @param date 日期
     */
    public static boolean isFirstDayOfWeek(LocalDate date) {
        return date.getDayOfWeek().equals(DayOfWeek.MONDAY);
    }

    /**
     * 本周第一天.
     *
     * @param date 日期
     */
    public static boolean isFirstDayOfWeek(LocalDateTime date) {
        return date.getDayOfWeek().equals(DayOfWeek.MONDAY);
    }

    /**
     * 获取本周第一天.
     *
     * @param date 日期
     */
    public static LocalDate firstDayOfWeek(LocalDate date) {
        return date.with(DayOfWeek.MONDAY);
    }

    /**
     * 获取本周第一天.
     *
     * @param date 日期
     */
    public static LocalDateTime firstDayOfWeek(LocalDateTime date) {
        return date.with(DayOfWeek.MONDAY);
    }

    /**
     * 本周最后一天.
     *
     * @param date 日期
     */
    public static boolean isLastDayOfWeek(LocalDate date) {
        return date.getDayOfWeek().equals(DayOfWeek.SUNDAY);
    }

    /**
     * 本周最后一天.
     *
     * @param date 日期
     */
    public static boolean isLastDayOfWeek(LocalDateTime date) {
        return date.getDayOfWeek().equals(DayOfWeek.SUNDAY);
    }

    /**
     * 本月第一天.
     *
     * @param date 日期
     */
    public static boolean isFirstDayOfMonth(LocalDate date) {
        return firstDayOfMonth(date).equals(date);
    }

    /**
     * 本月第一天.
     *
     * @param date 日期
     */
    public static boolean isFirstDayOfMonth(LocalDateTime date) {
        return firstDayOfMonth(date).equals(date);
    }

    /**
     * 本月第一天.
     *
     * @param date 日期
     */
    public static LocalDate firstDayOfMonth(LocalDate date) {
        return date.with(java.time.temporal.TemporalAdjusters.firstDayOfMonth());
    }

    /**
     * 本月第一天.
     *
     * @param date 日期
     */
    public static LocalDateTime firstDayOfMonth(LocalDateTime date) {
        return date.with(java.time.temporal.TemporalAdjusters.firstDayOfMonth());
    }

    /**
     * 本月最后一天.
     *
     * @param date 日期
     */
    public static boolean isLastDayOfMonth(LocalDate date) {
        return lastDayOfMonth(date).equals(date);
    }

    /**
     * 本月最后一天.
     *
     * @param date 日期
     */
    public static boolean isLastDayOfMonth(LocalDateTime date) {
        return lastDayOfMonth(date).equals(date);
    }

    public static LocalDate lastDayOfMonth(LocalDate date) {
        return date.with(java.time.temporal.TemporalAdjusters.lastDayOfMonth());
    }

    public static LocalDateTime lastDayOfMonth(LocalDateTime date) {
        return date.with(java.time.temporal.TemporalAdjusters.lastDayOfMonth());
    }

    /**
     * 获取偏离今天的天数的日期.
     *
     * @param offsetDays 偏离天数
     */
    public static LocalDate getOffsetToday(int offsetDays) {
        return LocalDate.now().plusDays(offsetDays);
    }

    /**
     * 得到偏离现在天数的时间  +几天后, -几天前.
     *
     * @param date       日期 yyyy-MM-dd
     * @param offsetDays 偏离天数
     * @return yyyy-MM-dd
     */
    public static String getOffsetDate(String date, int offsetDays) {
        return toShortTime(LocalDate.parse(date, DateTimeFormatter.ofPattern(PATTERN_SHORT_TIME)).plusDays(offsetDays));
    }

    /**
     * 获取凌晨时间.
     *
     * @return yyyy-MM-dd 24:00:00
     */
    public static LocalDateTime todayEndTime() {
        return LocalDateTime.now().with(LocalTime.MAX);
    }

    /**
     * 获取缓存的总秒数(24:00:00过期).
     *
     * @return 返回到24:00:00的秒数
     */
    public static long todayEndExpireSeconds() {
        return secondsOfTimePeriod(LocalDateTime.now(), todayEndTime());
    }

    /**
     * 获取两个时间的时间差.
     *
     * @param startTime 起始时间
     * @param endTime   结束时间
     * @return 秒
     */
    public static long secondsOfTimePeriod(LocalDateTime startTime, LocalDateTime endTime) {
        return ChronoUnit.SECONDS.between(startTime, endTime);
    }

    /**
     * 获取缓存的总秒数(多少天对应的总秒数).
     *
     * @return 返回的秒数
     */
    public static long expireSecondsOfDays(int keepDays) {
        return keepDays * SECONDS_PRE_DAY;
    }

    /**
     * 得到偏离现在分钟数的时间  +几分钟后, -几分钟前.
     *
     * @param date          日期
     * @param offsetMinutes 偏离分钟数
     */
    public static LocalDateTime offsetMinutes(LocalDateTime date, int offsetMinutes) {
        return date.plusMinutes(offsetMinutes);
    }

    /**
     * 获取指定整形日期格式化字符串.
     *
     * @param date   整形日期
     * @param format 返回的日期格式
     * @return 格式化日期字符串
     */
    public static String formatIntDate(int date, String format) {
        return parseIntDate(date).format(DateTimeFormatter.ofPattern(format));
    }
}
