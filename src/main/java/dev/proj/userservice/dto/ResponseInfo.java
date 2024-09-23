package dev.proj.userservice.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResponseInfo {
    private String message;
    private int statusCode;
}
