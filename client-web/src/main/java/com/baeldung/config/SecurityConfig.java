package com.baeldung.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
				.oauth2Login(oauth2Login -> oauth2Login.loginPage("/oauth2/authorization/articles-client-oidc"))
				.oauth2Client(withDefaults());
		return http.build();
	}

}