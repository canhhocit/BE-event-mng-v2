package com.sa.event_mng.service;

import com.sa.event_mng.dto.request.UserUpdateRequest;
import com.sa.event_mng.dto.response.UserResponse;
import com.sa.event_mng.exception.AppException;
import com.sa.event_mng.exception.ErrorCode;
import com.sa.event_mng.mapper.UserMapper;
import com.sa.event_mng.model.entity.User;
import com.sa.event_mng.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserService {
    UserRepository userRepository;
    UserMapper userMapper;
    PasswordEncoder passwordEncoder;

    @PreAuthorize("isAuthenticated()")
    public UserResponse getMyInfo() {
        var context = SecurityContextHolder.getContext();
        String name = context.getAuthentication().getName();

        User user = userRepository.findByUsername(name)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        return userMapper.toUserResponse(user);
    }

    // findOne
    public UserResponse getUserByUsername(String username) {
        User user = userRepository.findByUsernameAndEnabledTrue(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        return userMapper.toUserResponse(user);
    }

    // findAll
    // @PreAuthorize("hasRole('ADMIN')")
    // public Page<UserResponse> getUsers(PageRequest pageRequest) {
    //     Page<User> userPage = userRepository.findAllByEnabledTrue(pageRequest);
    //     return userPage.map(userMapper::toUserResponse);
    // }

    @PreAuthorize("hasRole('ADMIN')")
    public Page<UserResponse> getUsers(String search, PageRequest pageRequest) {
        Page<User> userPage;
        if (search == null || search.isBlank()) {
            userPage = userRepository.findAll(pageRequest);
        } else {
            userPage = userRepository
                    .findByUsernameContainingIgnoreCaseOrFullNameContainingIgnoreCase(
                            search, search, pageRequest);
        }
        return userPage.map(userMapper::toUserResponse);
    }

    // Update
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public UserResponse updateUser(String username, UserUpdateRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        if (!user.isEnabled())
            throw new AppException(ErrorCode.USER_NOT_EXISTED);

        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmailAndEnabledTrue(request.getEmail())) {
                throw new AppException(ErrorCode.EMAIL_EXISTED);
            }
            user.setEmail(request.getEmail());
        }

        if (request.getPassword() != null && !request.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        if (request.getFullName() != null)
            user.setFullName(request.getFullName());
        if (request.getPhone() != null)
            user.setPhone(request.getPhone());
        if (request.getAddress() != null)
            user.setAddress(request.getAddress());

        return userMapper.toUserResponse(userRepository.save(user));
    }

    // Delete
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteUser(String username) {
        User user = userRepository.findByUsernameAndEnabledTrue(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        user.setEnabled(false);
        user.setVerificationToken("");
        userRepository.save(user);
        return "deleted";
    }

    // Unlock
    @PreAuthorize("hasRole('ADMIN')")
    public String unlockUser(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        user.setEnabled(true);
        userRepository.save(user);
        return "unlocked";
    }
}