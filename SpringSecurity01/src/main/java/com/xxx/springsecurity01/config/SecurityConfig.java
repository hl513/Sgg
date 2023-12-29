package com.xxx.springsecurity01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.AuthorizeHttpRequestsDsl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  // 开启SpringSecurity 默认注册大量的过滤器 servlet filter
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // AuthorizeHttpRequests:针对http请求进行授权配置
        // login 登录页面需要匿名访问
        // permitAll 具有所有权限，可以匿名访问
        // anyRequest: 任何请求
        // authenticated 认证【登录】
        http.authorizeHttpRequests(AuthorizeHttpRequests ->
                AuthorizeHttpRequests
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated());
        http.formLogin(formLogin->
                formLogin
                        .loginPage("/login").permitAll()  // 登录页面
                        .loginProcessingUrl("/login")  // 登录接口，过滤器
                        .defaultSuccessUrl("/index") // 登录成功之后访问的页面

        );
        http.csrf().disable();
        // 退出
        http.logout(logout->logout.invalidateHttpSession(true));
        return http.build();
    }


}
