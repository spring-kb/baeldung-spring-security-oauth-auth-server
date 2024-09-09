package com.baeldung.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.config.Customizer;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	/*
	 * @Bean
	 * SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	 * http
	 * .authorizeHttpRequests(authorizeRequests ->
	 * authorizeRequests.anyRequest().authenticated())
	 * .oauth2Login(oauth2Login ->
	 * oauth2Login.loginPage("/oauth2/authorization/articles-client-oidc"))
	 * .oauth2Client(withDefaults());
	 * return http.build();
	 * }
	 */
	@Bean
	public SecurityWebFilterChain securityWebFilterChain(
			ServerHttpSecurity http) {

		// http.httpBasic(Customizer.withDefaults());
		http.authorizeExchange(
				c -> c.anyExchange()
						.authenticated());

		http.oauth2Login(Customizer.withDefaults())
				.formLogin(login -> login.loginPage("/oauth2/authorization/articles-client-oidc"));
		http.oauth2Client(Customizer.withDefaults());

		return http.build();
	}
}