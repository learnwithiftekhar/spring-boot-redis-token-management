package com.learnwithiftekhar.redissessionmanagement;

import com.learnwithiftekhar.redissessionmanagement.model.Role;
import com.learnwithiftekhar.redissessionmanagement.model.User;
import com.learnwithiftekhar.redissessionmanagement.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class RedisSessionManagementApplication {

    public static void main(String[] args) {
        SpringApplication.run(RedisSessionManagementApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            User user = new User();
            user.setUsername("admin");
            user.setPassword(passwordEncoder.encode("admin"));
            user.setRole(Role.ADMIN);
            userRepository.save(user);
        };
    }
}
