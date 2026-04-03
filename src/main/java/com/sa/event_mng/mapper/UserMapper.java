package com.sa.event_mng.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

import com.sa.event_mng.dto.request.UserCreateRequest;
import com.sa.event_mng.dto.request.UserUpdateRequest;
import com.sa.event_mng.dto.response.UserResponse;
import com.sa.event_mng.model.entity.User;

import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "verificationToken", ignore = true)
    User toUser(UserCreateRequest request);

    UserResponse toUserResponse(User user);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "username", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "verificationToken", ignore = true)
    void updateUser(@MappingTarget User user, UserUpdateRequest request);
}
