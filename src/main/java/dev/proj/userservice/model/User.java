package dev.proj.userservice.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "user_service")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(unique = true, name = "email")
    private String email;

    @Column(name = "user_password")
    private String userPassword;

    @Column(name = "role")
    private Role role;

    @Column(name = "phone_number")
    private String phoneNumber;
}
