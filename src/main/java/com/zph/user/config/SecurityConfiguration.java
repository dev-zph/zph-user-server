package com.zph.user.config;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.LocalTokenServices;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * @notes 安全校验
 * @autho zph
 * @createTime 2018/9/30 12:41
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    final static String IGNORE_RESOURCE_URL[] = new String[]{"/v2/api-docs"};

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().disable()
                .authorizeRequests().regexMatchers(IGNORE_RESOURCE_URL).permitAll().and()
                .authorizeRequests().anyRequest().authenticated().and()
                .csrf().disable().exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                response.setContentType("application/json");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getOutputStream().println("未授权");
            }
        })
                .and().addFilterAfter(ssoFilter(), UsernamePasswordAuthenticationFilter.class).addFilterBefore(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                try {
                    filterChain.doFilter(request, response);
                } catch (Exception e) {
                    // custom error response class used across my project
                    response.setStatus(HttpStatus.OK.value());
                    response.setContentType("application/json;charset=utf-8");
                    response.getWriter().write("未授权");
                }
            }
        }, MyOAuth2ClientAuthFilter.class);
    }

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Autowired
    private AuthorizationCodeResourceDetails codeResourceDetails;

    @Autowired
    private ResourceServerProperties resourceServerProperties;

    private Filter ssoFilter() {
        MyOAuth2ClientAuthFilter zbyCloudFilter = new MyOAuth2ClientAuthFilter("/**");
        OAuth2RestTemplate oauth2RestTemplate = new OAuth2RestTemplate(codeResourceDetails, oauth2ClientContext);
        zbyCloudFilter.setRestTemplate(oauth2RestTemplate);
        LocalTokenServices tokenServices = new LocalTokenServices();
        tokenServices.setJwtTokenEnhancer(jwtAccessTokenConverter());
        zbyCloudFilter.setContinueChainBeforeSuccessfulAuthentication(true);//不做跳转继续执行请求
        zbyCloudFilter.setSessionAuthenticationStrategy(new SessionAuthenticationStrategy() {
            @Override
            public void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws SessionAuthenticationException {
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        });
        zbyCloudFilter.setTokenServices(tokenServices);
        return zbyCloudFilter;
    }

    public static class MyOAuth2ClientAuthFilter extends OAuth2ClientAuthenticationProcessingFilter {
        private TokenExtractor tokenExtractor = new BearerTokenExtractor();

        private List<Pattern> ignoreUrlPatternList = new ArrayList<>();

        LocalTokenServices tokenServices = new LocalTokenServices();

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
            if(ignoreUrlPatternList.isEmpty()) {
                synchronized (ignoreUrlPatternList) {
                    if (ignoreUrlPatternList.isEmpty()) {
                        for(String patternStr : IGNORE_RESOURCE_URL){
                            ignoreUrlPatternList.add(Pattern.compile(patternStr));
                        }
                    }
                }
            }
            for(Pattern pattern : ignoreUrlPatternList){
                if( pattern.matcher(((HttpServletRequest)req).getRequestURI() ).matches() ){
                    chain.doFilter(req, res);
                    return;
                }
            }
            // super.doFilter(req, res, chain);

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
//				if(preAuthenticatedAuthenticationToken!=null) {
//					String token = (String) preAuthenticatedAuthenticationToken.getPrincipal();
//					this.restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken(token));
//				}
//				Authentication authentication = super.attemptAuthentication(request, response);

            String token = (String) preAuthenticatedAuthenticationToken.getPrincipal();
            Authentication authentication =  tokenServices.loadAuthentication(token);
            if(authentication instanceof OAuth2Authentication) {//获取子不语授权对象
                SecurityContextHolder.getContext().setAuthentication(authentication);
                OAuth2Authentication oAuth2Authentication = (OAuth2Authentication)authentication;
                for(GrantedAuthority grantedAuthority : oAuth2Authentication.getUserAuthentication().getAuthorities()){
                    /*if(grantedAuthority.getAuthority().startsWith("ZbyPrincipal")){
                        int idx = grantedAuthority.getAuthority().indexOf(':');
                        String compositePrincipalJson = new String(Base64.decodeBase64(grantedAuthority.getAuthority().substring(idx+1)));
                        CompositePrincipal compositePrincipal = MyEasyJsonUtil.string2json(compositePrincipalJson, CompositePrincipal.class);
                        //20180703多角色变动, 原客户端存的令牌需要强制失效掉
                        if(compositePrincipal==null || compositePrincipal.getBasicUser().getRoleList()==null){
                            throw BusinessException.create("令牌失效");
                        }

                        MySecurityContextHolder.setCompositePrincipal(compositePrincipal);
                        MySecurityContextHolder.setOauth2Authentication(oAuth2Authentication);
                        MySecurityContextHolder.setOauth2AccessToken(tokenServices.readAccessToken(token));
                    }*/
                }
            }
            return authentication;
        }
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("keystore.jks"), "mypass".toCharArray())
                .getKeyPair("mytest");
        converter.setKeyPair(keyPair);
        return converter;
    }
}
