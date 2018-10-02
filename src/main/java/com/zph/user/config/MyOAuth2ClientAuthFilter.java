package com.zph.user.config;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.LocalTokenServices;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.util.regex.Pattern;

/**
 * @notes 请求token验证拦截器
 * @autho zph
 * @createTime 2018/10/1 10:53
 */
public class MyOAuth2ClientAuthFilter extends OAuth2ClientAuthenticationProcessingFilter {

    private TokenExtractor tokenExtractor = new BearerTokenExtractor();
    private LocalTokenServices tokenServices = new LocalTokenServices();

    public MyOAuth2ClientAuthFilter(String defaultFilterProcessesUrl){
        super(defaultFilterProcessesUrl);
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "mypass".toCharArray())
                .getKeyPair("mytest");
        converter.setKeyPair(keyPair);
        tokenServices.setJwtTokenEnhancer(converter);
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        try {
            attemptAuthentication(request, response);
        }catch (Exception e){
            throw new ServletException(e);
        }
        chain.doFilter(req, res);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication preAuthenticatedAuthenticationToken = tokenExtractor.extract(request);
        String token = (String) preAuthenticatedAuthenticationToken.getPrincipal();
        Authentication authentication =  tokenServices.loadAuthentication(token);
        if(authentication instanceof OAuth2Authentication) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)authentication;
            for(GrantedAuthority grantedAuthority : oAuth2Authentication.getUserAuthentication().getAuthorities()){

            }
        }
        return authentication;
    }
}
