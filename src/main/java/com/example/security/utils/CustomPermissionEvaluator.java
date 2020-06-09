package com.example.security.utils;

import com.example.security.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;

//@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(CustomPermissionEvaluator.class);

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        Collection<? extends GrantedAuthority> grantedAuthorities = authentication.getAuthorities();
        Object user =authentication.getPrincipal();
        for (GrantedAuthority grantedAuthority: grantedAuthorities){
            System.out.println("haspermission验证成功"+grantedAuthority.getAuthority());
            if (permission.equals(grantedAuthority.getAuthority())){
                log.info(user.toString() + "：" + permission + "权限通过");
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
