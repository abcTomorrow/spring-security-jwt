package com.wojiushiwo.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author myk
 * @create 2020/10/28 下午4:44
 */
@Data
@ConfigurationProperties(prefix = "jwt")
@Component
public class JwtTokenUtil {

    private String secret;

    private Long expiration;

    private String header;

    /**
     * 生成token 令牌
     *
     * @param userDetails
     * @return 令牌
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>(2);
        claims.put("sub", userDetails.getUsername());
        claims.put("created", new Date());

        return generateToken(claims);
    }


    private String generateToken(Map<String, Object> claims) {
        Date expirationDate = new Date(System.currentTimeMillis() + expiration);
        return Jwts.builder().setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    /**
     * 从令牌中获取用户名
     *
     * @param token 令牌
     * @return 用户名
     */
    public String getUserNameFromToken(String token) {
        Claims claims = this.getClaimsFromToken(token);
        return claims.getSubject();
    }

    /**
     * 从令牌中获取数据声明
     *
     * @param token
     * @return
     */
    private Claims getClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    /**
     * 判断令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public Boolean isTokenExpired(String token) {
        Claims claims = getClaimsFromToken(token);
        Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }

    /**
     * 刷新令牌
     *
     * @param token 原令牌
     * @return
     */
    public String refreshToken(String token) {

        Claims claims = getClaimsFromToken(token);
        claims.put("created", new Date());
        return generateToken(claims);
    }

    /**
     * 验证令牌
     *
     * @param token       令牌
     * @param userDetails 用户
     * @return 是否有效
     */
    public Boolean validateToken(String token, UserDetails userDetails) {

        String userNameFromToken = getUserNameFromToken(token);
        return Objects.equals(userNameFromToken, userDetails.getUsername()) && !isTokenExpired(token);
    }


}
