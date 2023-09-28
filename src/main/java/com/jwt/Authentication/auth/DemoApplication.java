package com.jwt.Authentication.auth;

import com.jwt.Authentication.auth.Entity.AppRole;
import com.jwt.Authentication.auth.Entity.AppUser;
import com.jwt.Authentication.auth.Services.AccountService;
import com.jwt.Authentication.auth.security.RsaKeysConfig;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)

public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}
	@Bean
	CommandLineRunner start(AccountService accountService, PasswordEncoder passwordEncoder){
		return args -> {
			accountService.newUser(AppUser.builder().username("user1").password(passwordEncoder.encode("1234")).build());
			accountService.newUser(AppUser.builder().username("user2").password(passwordEncoder.encode("1234")).build());
			accountService.newUser(AppUser.builder().username("admin").password(passwordEncoder.encode("1234")).build());
			accountService.newRole(AppRole.builder().roleName("USER").build());
			accountService.newRole(AppRole.builder().roleName("ADMIN").build());
			accountService.addRoleToUser("user1","USER");
			accountService.addRoleToUser("user2","USER");
			accountService.addRoleToUser("admin","USER");
			accountService.addRoleToUser("admin","ADMIN");
		};
	}
	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
}

