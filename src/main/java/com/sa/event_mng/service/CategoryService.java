package com.sa.event_mng.service;

import com.sa.event_mng.dto.request.CategoryRequest;
import com.sa.event_mng.dto.response.CategoryResponse;
import com.sa.event_mng.exception.AppException;
import com.sa.event_mng.exception.ErrorCode;
import com.sa.event_mng.mapper.CategoryMapper;
import com.sa.event_mng.model.entity.Category;
import com.sa.event_mng.repository.CategoryRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class CategoryService {

    CategoryRepository categoryRepository;
    CategoryMapper categoryMapper;

    @PreAuthorize("hasRole('ADMIN')")
    public CategoryResponse create(CategoryRequest request) {
        Category category = Category.builder()
                .name(request.getName())
                .description(request.getDescription())
                .build();

        return categoryMapper.toCategoryResponse(categoryRepository.save(category));
    }

    public List<CategoryResponse> getAll() {
        return categoryRepository.findAll().stream()
                .map(categoryMapper::toCategoryResponse)
                .toList();
    }

    public CategoryResponse getById(Long id) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.CATEGORY_NOT_FOUND));
        return categoryMapper.toCategoryResponse(category);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public CategoryResponse update(Long id, CategoryRequest request) {
        Category category = categoryRepository.findById(id)
                .orElseThrow(() -> new AppException(ErrorCode.CATEGORY_NOT_FOUND));
        category.setName(request.getName());
        category.setDescription(request.getDescription());
        return categoryMapper.toCategoryResponse(categoryRepository.save(category));
    }

    @PreAuthorize("hasRole('ADMIN')")
    public void delete(Long id) {
        categoryRepository.deleteById(id);
    }
}
