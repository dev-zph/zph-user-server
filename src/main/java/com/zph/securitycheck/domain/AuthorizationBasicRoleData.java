package com.zph.securitycheck.domain;

import lombok.Data;

/**
 * @notes 登入用户权限配置数据
 * @autho zph
 * @createTime 2018/9/22 19:40
 */
@Data
public class AuthorizationBasicRoleData {
    /**
     * ID
     */
    private Integer roleId;
    /**
     * 角色代码
     */
    private String roleCode;

    /**
     * 角色名称
     */
    private String roleName;
}
