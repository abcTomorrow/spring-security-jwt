package com.wojiushiwo.jwt.service;

import com.wojiushiwo.jwt.exception.CustomException;
import com.wojiushiwo.jwt.exception.CustomExceptionType;
import com.wojiushiwo.jwt.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

/**
 * @author myk
 * @create 2020/10/28 下午5:03
 */
@Service
public class JwtAuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    public String login(String userName, String password) {

        Authentication authenticate = null;
        try {
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userName, password);

            authenticate = authenticationManager.authenticate(token);

            SecurityContextHolder.getContext().setAuthentication(authenticate);
        } catch (AuthenticationException e) {
            throw new CustomException(CustomExceptionType.USER_INPUT_ERROR, "用户名或密码不正确");
        }


        //生成JWT
        UserDetails userDetails = (UserDetails) authenticate.getPrincipal();
        return jwtTokenUtil.generateToken(userDetails);
    }


    public String refreshToken(String oldToken) {
        if (!jwtTokenUtil.isTokenExpired(oldToken)) {
            return jwtTokenUtil.refreshToken(oldToken);
        }
        return null;
    }

}
