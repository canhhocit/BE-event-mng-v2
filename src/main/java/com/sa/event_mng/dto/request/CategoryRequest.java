package com.sa.event_mng.dto.request;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CategoryRequest {
    @NotBlank(message = "CATEGORY_NAME_REQUIRED")
    @Size(min = 5, message = "CATEGORY_NAME_INVALID")
    private String name;
    private String description;
}
