package com.zph.securitycheck.webauthcheck;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.LocalTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyPair;

/**
 * @notes 拦截器，将用户信息 塞到SecurityContextHolder中
 * @autho zph
 * @createTime 2018/9/23 17:25
 */
@Component
public class AuthenticationTokenFilter extends GenericFilterBean {

    private TokenExtractor tokenExtractor = new BearerTokenExtractor();


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        Authentication preAuthenticatedAuthenticationToken = tokenExtractor.extract(httpRequest);
        if(preAuthenticatedAuthenticationToken!=null) {
            OAuth2Authentication oAuth2Authentication = null;
            try {
                LocalTokenServices localTokenServices = new LocalTokenServices();
                KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "mypass".toCharArray())
                        .getKeyPair("mytest");
                JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
                converter.setKeyPair(keyPair);
                localTokenServices.setJwtTokenEnhancer(converter);
                oAuth2Authentication = localTokenServices.loadAuthentication((String) preAuthenticatedAuthenticationToken.getPrincipal());
            }catch (Exception e){
                logger.error(e.getMessage());
            }
            if (SecurityContextHolder.getContext().getAuthentication() == null && oAuth2Authentication != null) {
                SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
