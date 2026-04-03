package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.EventResponse;
import com.sa.event_mng.model.entity.Event;
import com.sa.event_mng.model.entity.EventImage;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", uses = { TicketTypeMapper.class }, unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface EventMapper {
    @Mapping(target = "categoryName", source = "category.name")
    @Mapping(target = "organizerName", source = "organizer.fullName")
    @Mapping(target = "imageUrls", expression = "java(mapImages(event.getImages()))")
    EventResponse toEventResponse(Event event);

    default List<String> mapImages(List<EventImage> images) {
        if (images == null) {
            return List.of();
        }
        return images.stream().map(EventImage::getImageUrl).collect(Collectors.toList());
    }
}
