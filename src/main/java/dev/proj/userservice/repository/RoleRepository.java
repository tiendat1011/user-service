package dev.proj.userservice.repository;

import dev.proj.userservice.model.Role;
import dev.proj.userservice.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRole(RoleName roleName);
}
