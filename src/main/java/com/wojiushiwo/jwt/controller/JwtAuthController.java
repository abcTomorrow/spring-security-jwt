package com.wojiushiwo.jwt.controller;

import com.wojiushiwo.jwt.exception.AjaxResponse;
import com.wojiushiwo.jwt.exception.CustomException;
import com.wojiushiwo.jwt.exception.CustomExceptionType;
import com.wojiushiwo.jwt.service.JwtAuthService;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author myk
 * @create 2020/10/28 下午5:03
 */
@RestController
public class JwtAuthController {

    @Resource
    private JwtAuthService jwtAuthService;

    @PostMapping(value = "/authentication")
    public AjaxResponse login(@RequestBody Map<String, String> map) {
        String username = map.get("username");
        String password = map.get("password");
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) {
            return AjaxResponse.error(
                    new CustomException(
                            CustomExceptionType.USER_INPUT_ERROR, "用户名密码不能为空"));
        }
        try {
            return AjaxResponse.success(jwtAuthService.login(username, password));
        } catch (CustomException e) {
            return AjaxResponse.error(e);
        }
    }

    @PostMapping(value = "/refreshtoken")
    public AjaxResponse refresh(@RequestHeader("${jwt.header}") String token) {
        return AjaxResponse.success(jwtAuthService.refreshToken(token));
    }


    @GetMapping("/hello")
    public String sayHello(HttpServletRequest request) {
        return "world";
    }

}
