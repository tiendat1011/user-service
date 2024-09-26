package dev.proj.userservice.service;

import dev.proj.userservice.dto.UserRequest;
import dev.proj.userservice.dto.UserResponse;

public interface UserService {
    UserResponse createUser(UserRequest userRequest);
    UserResponse login(UserRequest userRequest);
}
