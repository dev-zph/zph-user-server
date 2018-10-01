package com.zph.securitycheck.webauthcheck;

import com.zph.securitycheck.tokenauthcheck.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;

import java.util.Collection;

/**
 * @notes 用户信息校验
 * @autho zph
 * @createTime 2018/9/23 16:49
 */
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = DigestUtils.md5DigestAsHex( ((String)authentication.getCredentials()).getBytes() );
        UserDetails userDetail = userDetailsService.loadUserByUsername(username);
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Collection<? extends GrantedAuthority> authorities = userDetail.getAuthorities();
        Authentication authentication1 = new UsernamePasswordAuthenticationToken(userDetail, password, authorities);
        return new UsernamePasswordAuthenticationToken(userDetail, password, authorities);
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
