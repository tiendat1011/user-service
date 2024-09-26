package dev.proj.userservice;

import dev.proj.userservice.model.Role;
import dev.proj.userservice.model.RoleName;
import dev.proj.userservice.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class UserServiceApplication /*implements CommandLineRunner*/ {
//    add role
//    @Autowired
//    RoleRepository roleRepository;

    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }

//    @Override
//    public void run(String... args) throws Exception {
//        Role admin = Role.builder()
//                .role(RoleName.ADMIN)
//                .build();
//
//        Role user = Role.builder()
//                .role(RoleName.USER)
//                .build();
//        roleRepository.save(admin);
//        roleRepository.save(user);
//    }
}
