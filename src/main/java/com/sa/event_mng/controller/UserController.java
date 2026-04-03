package com.sa.event_mng.controller;

import com.sa.event_mng.dto.request.UserUpdateRequest;
import com.sa.event_mng.dto.response.ApiResponse;
import com.sa.event_mng.dto.response.UserResponse;
import com.sa.event_mng.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
@Tag(name = "Người dùng", description = "Hồ sơ và quản lý người dùng")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

        private final UserService userService;

        @Operation(summary = "Lấy thông tin của chính mình", description = "Lấy thông tin hồ sơ của người dùng hiện đang đăng nhập")
        @GetMapping("/my-info")
        public ApiResponse<UserResponse> getMyInfo() {
                return ApiResponse.<UserResponse>builder()
                                .result(userService.getMyInfo())
                                .build();
        }

        @Operation(summary = "Lấy tất cả người dùng", description = "Lấy danh sách tất cả các người dùng đang hoạt động (Chỉ ADMIN)")
        // @GetMapping
        // public ApiResponse<Page<UserResponse>> getUsers(@RequestParam(defaultValue =
        // "1") int page,
        // @RequestParam(defaultValue = "10") int size) {
        // PageRequest pageRequest = PageRequest.of(
        // page - 1, size,
        // Sort.by("createdAt").descending());
        // return ApiResponse.<Page<UserResponse>>builder()
        // .result(userService.getUsers(pageRequest))
        // .build();
        // }
        @GetMapping
        public ApiResponse<Page<UserResponse>> getUsers(
                        @RequestParam(defaultValue = "1") int page,
                        @RequestParam(defaultValue = "10") int size,
                        @RequestParam(defaultValue = "") String search) {
                PageRequest pageRequest = PageRequest.of(
                                page - 1, size, Sort.by("createdAt").descending());
                return ApiResponse.<Page<UserResponse>>builder()
                                .result(userService.getUsers(search, pageRequest))
                                .build();
        }

        @Operation(summary = "Lấy người dùng theo Username", description = "Lấy thông tin cụ thể của người dùng theo username")
        @GetMapping("/{username}")
        public ApiResponse<UserResponse> getUser(@PathVariable String username) {
                return ApiResponse.<UserResponse>builder()
                                .result(userService.getUserByUsername(username))
                                .build();
        }

        @Operation(summary = "Cập nhật người dùng", description = "Cập nhật thông tin hồ sơ của một người dùng cụ thể")
        @PutMapping("/{username}")
        public ApiResponse<UserResponse> updateUser(@PathVariable String username,
                        @RequestBody @Valid UserUpdateRequest request) {
                return ApiResponse.<UserResponse>builder()
                                .result(userService.updateUser(username, request))
                                .build();
        }

        @Operation(summary = "Xóa người dùng", description = "Vô hiệu hóa tài khoản người dùng theo username(ADMIN)")
        @DeleteMapping("/{username}")
        public ApiResponse<String> deleteUser(@PathVariable String username) {
                return ApiResponse.<String>builder()
                                .result(userService.deleteUser(username))
                                .build();
        }

        @Operation(summary = "Mở khóa người dùng", description = "Mở khóa tài khoản người dùng theo username(ADMIN)")
        @PatchMapping("/{username}/unlock")
        public ApiResponse<String> unlockUser(@PathVariable String username) {
                return ApiResponse.<String>builder()
                                .result(userService.unlockUser(username))
                                .build();
        }
}