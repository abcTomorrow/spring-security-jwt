package com.wojiushiwo.jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(basePackages = "com.wojiushiwo.jwt.mapper")
public class JwtServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtServerApplication.class, args);
    }

}
