package dev.proj.userservice.service;

import dev.proj.userservice.dto.ResponseInfo;
import dev.proj.userservice.dto.UserRequest;
import dev.proj.userservice.dto.UserResponse;
import dev.proj.userservice.model.User;
import dev.proj.userservice.repository.UserRepository;
import dev.proj.userservice.utils.UserUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

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
                .userPassword(userRequest.getPassword())
                .phoneNumber(userRequest.getPhone())
                .build();
        userRepository.save(savedUser);

        return UserResponse.builder()
                .responseInfo(ResponseInfo.builder()
                        .message(UserUtils.CREATE_USER_SUCCESS_MESSAGE)
                        .statusCode(UserUtils.CREATE_USER_SUCCESS_CODE)
                        .build())
                .token(null)
                .build();
    }
}
