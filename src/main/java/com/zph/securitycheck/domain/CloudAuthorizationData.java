package com.zph.securitycheck.domain;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * @notes 分布式授权对象 符合账户权限信息
 * @autho zph
 * @createTime 2018/9/22 18:00
 */
@Data
public class CloudAuthorizationData implements Serializable {

    private AuthorizationBasicUserData authorizationBasicUserData;
    @Data
    public static class AuthorizationBasicUserData implements Serializable {
        /**
         * ID
         */
        private Integer userId;

        /**
         * 用户代码
         */
        private String userCode;

        /**
         * 用户名称
         */
        private String userName;

        /**
         * 密码
         */
        private String password;

        /**
         * 用户权限
         */
        private List<AuthorizationBasicRoleData> authorizationBasicRoleDataList;

    }

}
