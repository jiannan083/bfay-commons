package cn.bfay.commons.util;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * HttpUtils.
 *
 * @author wangjiannan
 */
public class HttpUtils {
    /**
     * 最大重试次数阈值.
     */
    private static final int MAX_RETRY_TIMES = 3;
    /**
     * 链接超时时间.
     */
    private static final int DEFAULT_CONNECT_TIMEOUT = 3000;
    /**
     * 缺省读取超时时间.
     */
    private static final int DEFAULT_SO_TIMEOUT = 5000;

    /**
     * 连接最大空闲时间.
     */
    private static final int CONNECTION_MAX_IDLE_TIME = 65;

    /**
     * 缺省post读取超时时间.
     */
    private static final int POST_SO_TIMEOUT = 5000;

    private static final Logger log = LoggerFactory.getLogger(HttpUtils.class);

    private static final RequestConfig DEFAULT_REQUEST_CONFIG;

    private static HttpClient httpClient;

    private static ObjectMapper mapper = new ObjectMapper();

    static {
        RequestConfig.Builder builder = RequestConfig.custom();
        builder.setSocketTimeout(DEFAULT_SO_TIMEOUT);
        builder.setConnectTimeout(DEFAULT_CONNECT_TIMEOUT);
        DEFAULT_REQUEST_CONFIG = builder.build();
        httpClient = HttpClientBuilder.create()
            .setMaxConnTotal(200)
            .setMaxConnPerRoute(100)
            .setRetryHandler(CustomHttpRequestRetryHandler.INSTANCE)
            .setDefaultRequestConfig(DEFAULT_REQUEST_CONFIG)
            //.evictExpiredConnections()
            .evictIdleConnections(CONNECTION_MAX_IDLE_TIME, TimeUnit.SECONDS)
            .build();

        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static void setHttpClient(HttpClient httpClient) {
        HttpUtils.httpClient = httpClient;
    }

    /**
     * 发送GET请求.
     *
     * @param url   GET请求地址
     * @param clazz 指定序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Class<T> clazz) {
        return HttpUtils.doGet(url, null, null, 0, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url  GET请求地址
     * @param type 指定序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, TypeReference type) {
        return HttpUtils.doGet(url, null, null, 0, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url          GET请求地址
     * @param parameterMap GET请求参数容器
     * @param clazz        指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, Class<T> clazz) {

        return HttpUtils.doGet(url, parameterMap, null, 0, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url          GET请求地址
     * @param parameterMap GET请求参数容器
     * @param type         指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, TypeReference type) {

        return HttpUtils.doGet(url, parameterMap, null, 0, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param connectTimeout 连接超时
     * @param socketTimeout  套接字超时
     * @param clazz          指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, int connectTimeout, int socketTimeout, Class<T> clazz) {

        return HttpUtils.doGet(url, null, null, null, 0, connectTimeout, socketTimeout, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param connectTimeout 连接超时
     * @param socketTimeout  套接字超时
     * @param type           指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, int connectTimeout, int socketTimeout, TypeReference type) {

        return HttpUtils.doGet(url, null, null, null, 0, connectTimeout, socketTimeout, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param parameterMap   GET请求参数容器
     * @param connectTimeout 连接超时
     * @param socketTimeout  套接字超时
     * @param clazz          指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, int connectTimeout, int socketTimeout, Class<T> clazz) {

        return HttpUtils.doGet(url, null, parameterMap, null, 0, connectTimeout, socketTimeout, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param parameterMap   GET请求参数容器
     * @param connectTimeout 连接超时
     * @param socketTimeout  套接字超时
     * @param type           指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, int connectTimeout, int socketTimeout, TypeReference type) {

        return HttpUtils.doGet(url, null, parameterMap, null, 0, connectTimeout, socketTimeout, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url       GET请求地址
     * @param headerMap GET请求头参数容器
     * @param clazz     指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map headerMap, Map paramMap, Class<T> clazz) {

        return HttpUtils.doGet(url, headerMap, paramMap, null, 0, -1, -1, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url       GET请求地址
     * @param headerMap GET请求头参数容器
     * @param type      指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map headerMap, Map paramMap, TypeReference type) {

        return HttpUtils.doGet(url, headerMap, paramMap, null, 0, -1, -1, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url       GET请求地址
     * @param proxyUrl  代理服务器地址
     * @param proxyPort 代理服务器端口号
     * @param clazz     指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, String proxyUrl, int proxyPort, Class<T> clazz) {

        return HttpUtils.doGet(url, null, proxyUrl, proxyPort, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url       GET请求地址
     * @param proxyUrl  代理服务器地址
     * @param proxyPort 代理服务器端口号
     * @param type      指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, String proxyUrl, int proxyPort, TypeReference type) {

        return HttpUtils.doGet(url, null, proxyUrl, proxyPort, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url          GET请求地址
     * @param parameterMap GET请求参数容器
     * @param proxyUrl     代理服务器地址
     * @param proxyPort    代理服务器端口号
     * @param clazz        指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, String proxyUrl, int proxyPort, Class<T> clazz) {

        return doGet(url, null, parameterMap, proxyUrl, proxyPort, -1, -1, clazz);
    }

    /**
     * 发送GET请求.
     *
     * @param url          GET请求地址
     * @param parameterMap GET请求参数容器
     * @param proxyUrl     代理服务器地址
     * @param proxyPort    代理服务器端口号
     * @param type         指定返回值序列化类型
     * @return 返回指定类型的实体
     */
    public static <T> T doGet(String url, Map parameterMap, String proxyUrl, int proxyPort, TypeReference type) {

        return doGet(url, null, parameterMap, proxyUrl, proxyPort, -1, -1, type);
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param headerMap      GET请求头参数容器
     * @param parameterMap   query string
     * @param proxyUrl       代理服务器地址
     * @param proxyPort      代理服务器端口号
     * @param connectTimeout 链接超时时间
     * @param socketTimeout  读取超时时间
     * @param clazz          返回值类型
     * @return 返回指定类型实体
     */
    private static <T> T doGet(String url, Map headerMap, Map parameterMap, String proxyUrl, int proxyPort,
                               int connectTimeout, int socketTimeout, Class<T> clazz) {

        HttpUriRequest request = buildRequest(url, headerMap, parameterMap, proxyUrl, proxyPort, connectTimeout,
            socketTimeout);
        return executeRequest(request, new CustomResponseHandler<T>(clazz));
    }

    /**
     * 发送GET请求.
     *
     * @param url            GET请求地址
     * @param headerMap      GET请求头参数容器
     * @param parameterMap   query string
     * @param proxyUrl       代理服务器地址
     * @param proxyPort      代理服务器端口号
     * @param connectTimeout 链接超时时间
     * @param socketTimeout  读取超时时间
     * @param type           返回值类型
     * @return 返回指定类型实体
     */
    private static <T> T doGet(String url, Map headerMap, Map parameterMap, String proxyUrl, int proxyPort,
                               int connectTimeout, int socketTimeout, TypeReference type) {

        HttpUriRequest request = buildRequest(url, headerMap, parameterMap, proxyUrl, proxyPort, connectTimeout,
            socketTimeout);
        return executeRequest(request, new CustomResponseHandler<T>(type));
    }

    private static <T> T executeRequest(HttpUriRequest request, ResponseHandler<T> handler) {
        try {
            return httpClient.execute(request, handler);
        } catch (HttpResponseException e) {
            log.error("calling url error, status code is " + e.getStatusCode() + ", url = " + request.getURI(), e);
            throw new CustomHttpResponseException(e);
        } catch (Exception ex) {
            log.error("calling url failed, url = " + request.getURI(), ex);
            throw new CustomClientProtocolException(ex);
        }
    }


    /**
     * 发送GET请求.
     *
     * @param url GET请求地址
     * @return 返回指定类型的实体
     */
    public static String doGetStringResult(String url) {
        return HttpUtils.doGet(url, null, null, null, 0, -1, -1, String.class);
    }

    /**
     * 发送GET请求.
     *
     * @param url          GET请求地址
     * @param parameterMap 请求参数
     * @return 返回指定类型的实体
     */
    public static String doGetStringResult(String url, Map parameterMap) {
        return HttpUtils.doGet(url, null, parameterMap, null, 0, -1, -1, String.class);
    }

    /**
     * 发送GET请求.
     *
     * @param url GET请求地址
     * @return 与当前请求对应的响应内容, 当请求失败时, 返回null
     */
    public static String doGetStringResult(String url, int readTimeouts) {
        return HttpUtils.doGet(url, null, null, null, 0, -1, readTimeouts, String.class);
    }

    /**
     * 发送post请求.
     *
     * @param url          POST请求地址
     * @param parameterMap POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static String doPostStringResult(String url, Map parameterMap) {
        return HttpUtils.doPost(url, null, parameterMap, null, null, null, 0, -1, -1, String.class);
    }

    /**
     * 发送post请求.
     *
     * @param url          POST请求地址
     * @param headerMap    请求头
     * @param parameterMap POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static String doPostStringResult(String url, Map headerMap, Map parameterMap) {
        return HttpUtils.doPost(url, headerMap, parameterMap, null, null, null, 0, -1, -1, String.class);
    }

    /**
     * post 方法.
     *
     * @param url         请求地址
     * @param requestBody 请求参数
     * @return String
     */
    public static String doPostJsonStringResult(String url, Object requestBody) {
        return doPost(url, null, requestBody, ContentType.APPLICATION_JSON.getMimeType(), Consts.UTF_8.toString(),
            null, 0, -1, -1, String.class);
    }

    /**
     * 发送POST请求.
     *
     * @param url         POST请求地址
     * @param requestBody POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Object requestBody, Class<T> clazz) {
        return HttpUtils.doPost(url, null, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, -1, -1, clazz);
    }

    /**
     * 发送POST请求.
     *
     * @param url         POST请求地址
     * @param requestBody POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Object requestBody, TypeReference type) {
        return HttpUtils.doPost(url, null, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, -1, -1, type);
    }

    /**
     * 发送POST请求.
     *
     * @param url         POST请求地址
     * @param headerMap   请求头参数容器
     * @param requestBody POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Map headerMap, Object requestBody, Class<T> clazz) {
        return HttpUtils.doPost(url, headerMap, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, -1, -1, clazz);
    }

    /**
     * 发送POST请求.
     *
     * @param url            POST请求地址
     * @param headerMap      请求头参数容器
     * @param requestBody    POST请求参数容器
     * @param connectTimeout 链接超时时间
     * @param socketTimeout  读取超时时间
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Map headerMap, Object requestBody,
                                   int connectTimeout, int socketTimeout, Class<T> clazz) {
        return HttpUtils.doPost(url, headerMap, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, connectTimeout, socketTimeout, clazz);
    }

    /**
     * 发送POST请求.
     *
     * @param url         POST请求地址
     * @param headerMap   请求头参数容器
     * @param requestBody POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Map headerMap, Object requestBody, TypeReference type) {
        return HttpUtils.doPost(url, headerMap, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, -1, -1, type);
    }

    /**
     * 发送POST请求.
     *
     * @param url            POST请求地址
     * @param headerMap      请求头参数容器
     * @param requestBody    POST请求参数容器
     * @param connectTimeout 链接超时时间
     * @param socketTimeout  读取超时时间
     * @return 返回指定类型的实体
     */
    public static <T> T doPostJson(String url, Map headerMap, Object requestBody,
                                   int connectTimeout, int socketTimeout, TypeReference type) {
        return HttpUtils.doPost(url, headerMap, requestBody, ContentType.APPLICATION_JSON.getMimeType(), null, null,
            0, connectTimeout, socketTimeout, type);
    }

    /**
     * 发送post请求.
     *
     * @param url          POST请求地址
     * @param parameterMap POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPost(String url, Map parameterMap, Class<T> clazz) {
        return HttpUtils.doPost(url, null, parameterMap, null, null, null, 0, -1, -1, clazz);
    }

    public static <T> T doPost(String url, Map parameterMap, TypeReference type) {
        return HttpUtils.doPost(url, null, parameterMap, null, null, null, 0, -1, -1, type);
    }

    /**
     * 发送post请求.
     *
     * @param url          POST请求地址
     * @param headerMap    请求头
     * @param parameterMap POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPost(String url, Map headerMap, Map parameterMap, Class<T> clazz) {
        return HttpUtils.doPost(url, headerMap, parameterMap, null, null, null, 0, -1, -1, clazz);
    }

    /**
     * 发送post请求.
     *
     * @param url          POST请求地址
     * @param headerMap    请求头
     * @param parameterMap POST请求参数容器
     * @return 返回指定类型的实体
     */
    public static <T> T doPost(String url, Map headerMap, Map parameterMap, TypeReference type) {
        return HttpUtils.doPost(url, headerMap, parameterMap, null, null, null, 0, -1, -1, type);
    }

    /**
     * 发送POST请求.
     *
     * @param url          POST请求地址
     * @param headerMap    POST请求头参数容器
     * @param paramCharset 参数字符集名称
     * @param proxyUrl     代理服务器地址
     * @param proxyPort    代理服务器端口号
     * @param clazz        指定返回值类型
     * @return 返回指定类型的实体
     */
    private static <T> T doPost(String url, Map headerMap, Object requestBody, String contentType, String paramCharset,
                                String proxyUrl, int proxyPort, int connectTimeout, int socketTimeout, Class<T> clazz) {

        HttpUriRequest postMethod = buildRequest(url, headerMap, requestBody, contentType, paramCharset, proxyUrl,
            proxyPort, connectTimeout, socketTimeout);
        return executeRequest(postMethod, new CustomResponseHandler<T>(clazz));
    }

    private static <T> T doPost(String url, Map headerMap, Object requestBody, String contentType, String paramCharset,
                                String proxyUrl, int proxyPort, int connectTimeout, int socketTimeout,
                                TypeReference type) {

        HttpUriRequest postMethod = buildRequest(url, headerMap, requestBody, contentType, paramCharset, proxyUrl,
            proxyPort, connectTimeout, socketTimeout);
        return executeRequest(postMethod, new CustomResponseHandler<T>(type));
    }


    private static HttpUriRequest buildRequest(String url, Map headerMap, Map parameterMap, String proxyUrl,
                                               int proxyPort, int connectTimeout, int socketTimeout) {
        HttpGet request;
        try {
            URIBuilder uriBuilder = new URIBuilder(url);
            if (parameterMap != null) {
                for (Object o : parameterMap.entrySet()) {
                    Map.Entry entry = (Map.Entry) o;
                    uriBuilder.addParameter(entry.getKey().toString(), entry.getValue().toString());
                }
            }
            request = new HttpGet(uriBuilder.build());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        final RequestConfig.Builder builder = RequestConfig.copy(DEFAULT_REQUEST_CONFIG);
        if (StringUtils.isNotBlank(proxyUrl)) {
            builder.setProxy(new HttpHost(proxyUrl, proxyPort));
        }
        if (connectTimeout != -1) {
            builder.setConnectTimeout(connectTimeout);
        }
        if (socketTimeout != -1) {
            builder.setSocketTimeout(socketTimeout);
        }
        RequestConfig config = builder.build();
        request.setConfig(config);

        addHeaders(request, headerMap);
        return request;
    }

    private static HttpUriRequest buildRequest(String url, Map headerMap, Object requestBody, String contentType,
                                               String paramCharset, String proxyUrl, int proxyPort,
                                               int connectTimeout, int socketTimeout) {
        if (StringUtils.isBlank(paramCharset)) {
            paramCharset = Consts.UTF_8.toString();
        }
        if (StringUtils.isBlank(contentType)) {
            contentType = ContentType.APPLICATION_FORM_URLENCODED.getMimeType();
        }

        final RequestConfig.Builder builder = RequestConfig.copy(DEFAULT_REQUEST_CONFIG);

        if (StringUtils.isNotBlank(proxyUrl)) {
            builder.setProxy(new HttpHost(proxyUrl, proxyPort));
        }

        if (connectTimeout != -1) {
            builder.setConnectTimeout(connectTimeout);
        }
        if (socketTimeout != -1) {
            builder.setSocketTimeout(socketTimeout);
        } else {
            builder.setSocketTimeout(POST_SO_TIMEOUT);
        }

        HttpPost request = new HttpPost(url);
        RequestConfig config = builder.build();
        request.setConfig(config);

        addHeaders(request, headerMap);

        addRequestBody(request, requestBody, contentType, paramCharset);
        return request;
    }

    private static void addRequestBody(HttpEntityEnclosingRequest request, Object requestBody, String contentType,
                                       String paramCharset) {
        Validate.notNull(request);
        if (null == requestBody) return;
        switch (contentType) {
            case "application/json":
                String jsonBody = null;
                try {
                    if (requestBody instanceof String) {
                        jsonBody = requestBody.toString();
                    } else {
                        jsonBody = mapper.writeValueAsString(requestBody);
                    }
                } catch (Exception e) {
                    log.warn("serialized json body failed, no request body set. " + e.getMessage(), e);
                    return;
                }
                request.setEntity(new StringEntity(jsonBody, ContentType.create(contentType, paramCharset)));
                break;
            case "application/x-www-form-urlencoded":
                if (requestBody instanceof Map) {
                    Map parameterMap = (Map) requestBody;
                    List<NameValuePair> formparams = new ArrayList<>(parameterMap.size());
                    for (Object o : parameterMap.entrySet()) {
                        Map.Entry entry = (Map.Entry) o;
                        formparams.add(
                            new BasicNameValuePair(entry.getKey().toString(), entry.getValue().toString()));
                    }
                    UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, Charset.forName(paramCharset));
                    request.setEntity(entity);
                } else {
                    log.warn("parse form parameter failed no request body set.");
                }
                break;
            default:
        }
    }

    private static void addHeaders(HttpUriRequest request, Map<String, String> headerMap) {
        Validate.notNull(request);
        if (null == headerMap) return;
        headerMap.entrySet().stream()
            .filter(map -> null != map.getKey() && null != map.getValue())
            .forEach(map -> {
                request.addHeader(map.getKey(), map.getValue());
            });
    }

    private static class CustomHttpRequestRetryHandler implements HttpRequestRetryHandler {
        static final CustomHttpRequestRetryHandler INSTANCE = new CustomHttpRequestRetryHandler();

        @Override
        public boolean retryRequest(IOException exception, int executionCount, HttpContext context) {
            if (executionCount >= MAX_RETRY_TIMES) {
                // Do not retry if over max retry count
                return false;
            }
            HttpClientContext clientContext = HttpClientContext.adapt(context);
            HttpRequest request = clientContext.getRequest();
            boolean idempotent = !(request instanceof HttpEntityEnclosingRequest);
            return idempotent && exception instanceof SocketTimeoutException;
        }
    }

    private static class CustomResponseHandler<T> implements ResponseHandler<T> {

        private Class<T> clazz;

        private TypeReference type;

        CustomResponseHandler(Class<T> clazz) {
            this.clazz = clazz;
        }

        CustomResponseHandler(TypeReference type) {
            this.type = type;
        }

        @Override
        public T handleResponse(HttpResponse response) throws IOException {
            StatusLine statusLine = response.getStatusLine();
            if (statusLine.getStatusCode() >= 300) {
                throw new HttpResponseException(
                    statusLine.getStatusCode(),
                    statusLine.getReasonPhrase());
            }
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                throw new ClientProtocolException("Response contains no content");
            }
            String responseStr = EntityUtils.toString(entity);
            if (null != clazz) {
                if (String.class.isAssignableFrom(clazz)) {
                    return (T) responseStr;
                }
                return mapper.readValue(responseStr, clazz);
            } else if (null != type) {
                return mapper.readValue(responseStr, type);
            } else {
                return null;
            }
        }
    }

    /**
     * custom http response exception.
     */
    public static class CustomHttpResponseException extends RuntimeException {
        private final int statusCode;

        public CustomHttpResponseException(int statusCode) {
            super();
            this.statusCode = statusCode;
        }

        public CustomHttpResponseException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        /**
         * construct.
         *
         * @param ex {@link HttpResponseException}
         */
        public CustomHttpResponseException(HttpResponseException ex) {
            super(ex);
            this.statusCode = ex.getStatusCode();
        }
    }

    /**
     * custom client protocol exception.
     */
    public static class CustomClientProtocolException extends RuntimeException {
        public CustomClientProtocolException() {
            super();
        }

        public CustomClientProtocolException(String message) {
            super(message);
        }

        public CustomClientProtocolException(ClientProtocolException ex) {
            super(ex);
        }

        public CustomClientProtocolException(Exception ex) {
            super(ex);
        }

    }
}
