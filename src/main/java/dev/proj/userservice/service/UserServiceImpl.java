package dev.proj.userservice.service;

import dev.proj.userservice.dto.ResponseInfo;
import dev.proj.userservice.dto.UserRequest;
import dev.proj.userservice.dto.UserResponse;
import dev.proj.userservice.model.Role;
import dev.proj.userservice.model.RoleName;
import dev.proj.userservice.model.User;
import dev.proj.userservice.repository.RoleRepository;
import dev.proj.userservice.repository.UserRepository;
import dev.proj.userservice.utils.UserUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserResponse createUser(UserRequest userRequest) {
        boolean isUserExists = userRepository.existsByEmail(userRequest.getEmail());

        if (isUserExists) {
            return UserResponse.builder()
                    .responseInfo(ResponseInfo.builder()
                            .message(UserUtils.USER_EXIST_MESSAGE)
                            .statusCode(UserUtils.USER_EXISTS_CODE)
                            .build())
                    .token(null)
                    .build();
        }
        User savedUser = User.builder()
                .firstName(userRequest.getFirstName())
                .lastName(userRequest.getLastName())
                .email(userRequest.getEmail())
                .password(passwordEncoder.encode(userRequest.getPassword()))
                .phoneNumber(userRequest.getPhone())
                .build();

        Set<Role> roles = new HashSet<>();
        userRequest.getRoles().forEach(roleName -> {
            Role role = roleRepository.findByRole(RoleName.valueOf(roleName))
                    .orElseThrow(() -> new RuntimeException(String.format("Role %s not found", roleName)));
            roles.add(role);
        });
        savedUser.setRole(roles);
        userRepository.save(savedUser);

        return UserResponse.builder()
                .responseInfo(ResponseInfo.builder()
                        .message(UserUtils.CREATE_USER_SUCCESS_MESSAGE)
                        .statusCode(UserUtils.CREATE_USER_SUCCESS_CODE)
                        .build())
                .token(null)
                .build();
    }

    @Override
    public UserResponse login(UserRequest userRequest) {
        return null;
    }
}
