package com.sa.event_mng.repository;

import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.model.enums.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByUsernameAndEnabledTrue(String username);

    Optional<User> findByEmailAndEnabledTrue(String email);

    Optional<User> findByIdAndEnabledTrue(Long id);

    Page<User> findAllByEnabledTrue(Pageable pageable);

    Optional<User> findByVerificationToken(String verificationToken);

    boolean existsByUsername(String username);

    boolean existsByEmailAndEnabledTrue(String email);

    Page<User> findByUsernameContainingIgnoreCaseOrFullNameContainingIgnoreCaseAndEnabledTrue(
            String username, String fullName, Pageable pageable);

    Page<User> findByUsernameContainingIgnoreCaseOrFullNameContainingIgnoreCase(
            String username, String fullName, Pageable pageable);

    List<User> findByRole(Role role);
}
