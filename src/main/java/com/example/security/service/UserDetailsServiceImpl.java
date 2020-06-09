package com.example.security.service;

import com.example.security.entity.JwtUser;
import com.example.security.entity.User;
import com.example.security.repository.UserRepository;
import com.example.security.utils.JwtTokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(s);
        JwtUser jwtUser = new JwtUser(user);
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        System.out.println("服务返回userdetails");
        grantedAuthorities.add(new SimpleGrantedAuthority("App\\Api\\Controllers\\UserController.index"));
        jwtUser.setAuthorities(grantedAuthorities);
        return new JwtUser(user);
    }

}
