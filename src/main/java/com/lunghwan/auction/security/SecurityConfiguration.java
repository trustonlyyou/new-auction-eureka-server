package com.lunghwan.auction.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableEurekaServer
public class SecurityConfiguration {

    @Value("${spring.security.user.name}")
    private String username;

    @Value("${spring.security.user.password}")
    private String password; // Jasypt가 자동으로 복호화된 값을 주입해줍니다.

    /**
     * BCrypt 알고리즘으로 패스워드 암호화
     * @return BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Security Filter Chain
     * @param http HttpSecurity
     * @return SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable); // CSRF 보호 비활성화
        // 모든 요청은 인증 필요
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());
        // 브라우저 팝업으로 로그인 (Basic Auth) -> 기본 인증 사용
        http.httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(BCryptPasswordEncoder encoder) {

        UserDetails user = User.builder()
                .username(username)
                .password(encoder.encode(password))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

}
