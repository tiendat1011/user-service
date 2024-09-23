package dev.proj.userservice.controller;

import dev.proj.userservice.dto.ResponseInfo;
import dev.proj.userservice.dto.UserRequest;
import dev.proj.userservice.dto.UserResponse;
import dev.proj.userservice.service.UserService;
import dev.proj.userservice.utils.UserUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping()
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserRequest userRequest, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseEntity.badRequest().body(
                    UserResponse.builder()
                            .responseInfo(ResponseInfo.builder()
                                    .message(bindingResult.getAllErrors().toString())
                                    .build())
                            .token(null)
                            .build());
        }

        UserResponse userResponse = userService.createUser(userRequest);
        if (userResponse.getResponseInfo().getStatusCode() == UserUtils.USER_EXISTS_CODE) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(userResponse);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(userResponse);
    }
}
