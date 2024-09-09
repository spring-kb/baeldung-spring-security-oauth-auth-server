package com.baeldung;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication
public class OAuth2ClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2ClientApplication.class, args);
	}

}
