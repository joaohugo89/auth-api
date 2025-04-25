package com.library.auth_api.config;

import com.library.auth_api.model.ERole;
import com.library.auth_api.model.Role;
import com.library.auth_api.model.User;
import com.library.auth_api.repositories.RoleRepository;
import com.library.auth_api.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Initialize roles if they don't exist
        initRoles();
        
        // Initialize default users if they don't exist
        initUsers();
    }

    private void initRoles() {
        if (roleRepository.count() == 0) {
            Role userRole = new Role(ERole.ROLE_USER);
            Role modRole = new Role(ERole.ROLE_MODERATOR);
            Role adminRole = new Role(ERole.ROLE_ADMIN);

            roleRepository.save(userRole);
            roleRepository.save(modRole);
            roleRepository.save(adminRole);
        }
    }

    private void initUsers() {
        if (userRepository.count() == 0) {
            // Create admin user
            User adminUser = new User(
                    "admin",
                    "admin@example.com",
                    passwordEncoder.encode("admin123")
            );

            Set<Role> adminRoles = new HashSet<>();
            roleRepository.findByName(ERole.ROLE_ADMIN).ifPresent(adminRoles::add);
            adminUser.setRoles(adminRoles);
            userRepository.save(adminUser);

            // Create regular user
            User regularUser = new User(
                    "user",
                    "user@example.com",
                    passwordEncoder.encode("user123")
            );

            Set<Role> userRoles = new HashSet<>();
            roleRepository.findByName(ERole.ROLE_USER).ifPresent(userRoles::add);
            regularUser.setRoles(userRoles);
            userRepository.save(regularUser);

            // Create moderator user
            User modUser = new User(
                    "moderator",
                    "moderator@example.com",
                    passwordEncoder.encode("mod123")
            );

            Set<Role> modRoles = new HashSet<>();
            roleRepository.findByName(ERole.ROLE_MODERATOR).ifPresent(modRoles::add);
            modUser.setRoles(modRoles);
            userRepository.save(modUser);
        }
    }
}
