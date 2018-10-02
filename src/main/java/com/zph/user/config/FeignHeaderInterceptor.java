package com.zph.user.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.apache.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * @notes 服务间token传递。拦截器：请求头设置身份信息
 * @autho zph
 * @createTime 2018/10/2 11:41
 */
@Component
public class FeignHeaderInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate template) {
        template.header(HttpHeaders.AUTHORIZATION, "Bearer"+SecurityContextHolder.getContext().getAuthentication().getDetails());
    }
}

