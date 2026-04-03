package com.sa.event_mng.controller;

import com.sa.event_mng.dto.request.CategoryRequest;
import com.sa.event_mng.dto.response.ApiResponse;
import com.sa.event_mng.dto.response.CategoryResponse;
import com.sa.event_mng.service.CategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/categories")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Tag(name = "Danh mục", description = "Quản lý danh mục sự kiện")
public class CategoryController {

    CategoryService categoryService;

    @PostMapping
    @Operation(summary = "Tạo danh mục mới (ADMIN)")
    public ApiResponse<CategoryResponse> create(@RequestBody @Valid CategoryRequest request) {
        return ApiResponse.<CategoryResponse>builder()
                .result(categoryService.create(request))
                .build();
    }

    @GetMapping
    @Operation(summary = "Lấy danh sách danh mục")
    public ApiResponse<List<CategoryResponse>> getAll() {
        return ApiResponse.<List<CategoryResponse>>builder()
                .result(categoryService.getAll())
                .build();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Lấy danh mục theo ID")
    public ApiResponse<CategoryResponse> getById(@PathVariable Long id) {
        return ApiResponse.<CategoryResponse>builder()
                .result(categoryService.getById(id))
                .build();
    }

    @PutMapping("/{id}")
    @Operation(summary = "Cập nhật danh mục (ADMIN)")
    public ApiResponse<CategoryResponse> update(@PathVariable Long id, @RequestBody @Valid CategoryRequest request) {
        return ApiResponse.<CategoryResponse>builder()
                .result(categoryService.update(id, request))
                .build();
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Xóa danh mục (ADMIN)")
    public ApiResponse<Void> delete(@PathVariable Long id) {
        categoryService.delete(id);
        return ApiResponse.<Void>builder().build();
    }
}
