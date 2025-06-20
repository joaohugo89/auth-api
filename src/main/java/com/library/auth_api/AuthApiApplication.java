package com.library.auth_api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaRepositories(basePackages = "com.library.auth_api.repositories")
@SpringBootApplication
public class AuthApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthApiApplication.class, args);
	}

}
