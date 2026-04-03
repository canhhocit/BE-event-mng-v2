package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.CategoryResponse;
import com.sa.event_mng.model.entity.Category;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CategoryMapper {
    CategoryResponse toCategoryResponse(Category category);
}
