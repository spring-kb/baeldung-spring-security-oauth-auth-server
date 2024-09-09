package com.baeldung.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class DefaultSecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain asFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration
				.applyDefaultSecurity(http);
		http.getConfigurer(
				OAuth2AuthorizationServerConfigurer.class)
				.oidc(Customizer.withDefaults());
		http.exceptionHandling((e) -> e.authenticationEntryPoint(
				new LoginUrlAuthenticationEntryPoint("/login")));
		return http.build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
			throws Exception {

		http.formLogin(Customizer.withDefaults());

		http.authorizeHttpRequests(
				c -> c.anyRequest().authenticated());

		http.csrf(csrf -> csrf.disable());

		return http.build();
	}

	@Bean
	UserDetailsService users() {
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		UserDetails user = User.builder()
				.username("admin")
				.password("password")
				.passwordEncoder(encoder::encode)
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	// @Bean
	// public AuthorizationServerSettings authorizationServerSettings() {
	// return AuthorizationServerSettings.builder().build();
	// }

	// @Bean
	// public JWKSource<SecurityContext> jwkSource()
	// throws NoSuchAlgorithmException {

	// KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	// keyPairGenerator.initialize(2048);
	// KeyPair keyPair = keyPairGenerator.generateKeyPair();
	// RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
	// RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	// RSAKey rsaKey = new RSAKey.Builder(publicKey)
	// .privateKey(privateKey)
	// .keyID(UUID.randomUUID().toString())
	// .build();
	// JWKSet jwkSet = new JWKSet(rsaKey);
	// return new ImmutableJWKSet<>(jwkSet);
	// }

	// @Bean
	// public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
	// return (context) -> {
	// if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
	// context.getClaims().claims((claims) -> {
	// Set<String> roles =
	// AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
	// .stream()
	// .map(c -> c.replaceFirst("^ROLE_", ""))
	// .collect(Collectors.collectingAndThen(Collectors.toSet(),
	// Collections::unmodifiableSet));
	// claims.put("roles", roles);
	// claims.put("priority", "HIGH");
	// });
	// }
	// };
	// }

}