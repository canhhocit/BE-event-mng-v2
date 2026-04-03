package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.TicketTypeResponse;
import com.sa.event_mng.model.entity.TicketType;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface TicketTypeMapper {
    TicketTypeResponse toTicketTypeResponse(TicketType ticketType);
}
