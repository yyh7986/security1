package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록된다
public class SecurityConfig {

    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        //user라는 url로 들어오면 인증이 필요하다
                        .requestMatchers("/user/**").authenticated()
                        //manager로 들어오면 MANAGER 인증 또는 ADMIN 인증이 필요하다
                        .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                        //admin으로 들어오면 ADMIN 권한이 있는 사람만 들어올 수 있다
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        //나머지 url은 전부 권한을 허용한다
                        .anyRequest().permitAll());

        http.formLogin(form ->
                form.loginPage("/loginForm")
                .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/")
        );
        return http.build();
    }
}
