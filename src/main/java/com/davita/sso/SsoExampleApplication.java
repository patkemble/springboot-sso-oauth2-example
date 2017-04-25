package com.davita.sso;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@ComponentScan
@RestController
@Slf4j
public class SsoExampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SsoExampleApplication.class, args);
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		log.info("user info name: {} and to string value: {}", principal.getName(), principal.toString());
		return principal;
	}

}

