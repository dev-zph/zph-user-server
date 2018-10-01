package com.zph.securitycheck.tokenauthcheck;

import com.zph.securitycheck.domain.AuthorizationBasicRoleData;
import com.zph.securitycheck.domain.CloudAuthorizationData;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * @notes 用户信息服务,认证用户信息
 * @autho zph
 * @createTime 2018/9/22 17:39
 */
@Component
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        //这里根据用户名称，查询用户信息
        CloudAuthorizationData cloudAuthorizationData = new CloudAuthorizationData();
        CloudAuthorizationData.AuthorizationBasicUserData authorizationBasicUserData = new CloudAuthorizationData.AuthorizationBasicUserData();
        authorizationBasicUserData.setUserCode("001");
        authorizationBasicUserData.setUserId(1);
        authorizationBasicUserData.setUserName("system");
        authorizationBasicUserData.setPassword("123456");
        List<AuthorizationBasicRoleData> authorizationBasicRoleDataList = new LinkedList<>();
        AuthorizationBasicRoleData roleData = new AuthorizationBasicRoleData();
        roleData.setRoleId(1);
        roleData.setRoleCode("admin");
        roleData.setRoleName("管理员");
        authorizationBasicRoleDataList.add(roleData);
        authorizationBasicUserData.setAuthorizationBasicRoleDataList(authorizationBasicRoleDataList);
        cloudAuthorizationData.setAuthorizationBasicUserData(authorizationBasicUserData);

        Collection<SimpleGrantedAuthority> collection = new ArrayList<>();
        authorizationBasicRoleDataList.forEach(item -> {
            collection.add(new SimpleGrantedAuthority(item.getRoleName()+":"+item.getRoleCode()));
        });
        return new User(authorizationBasicUserData.getUserName(),authorizationBasicUserData.getPassword(), collection);
    }
}
