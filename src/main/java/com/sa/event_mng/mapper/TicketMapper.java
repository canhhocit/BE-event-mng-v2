package com.sa.event_mng.mapper;

import com.sa.event_mng.dto.response.TicketResponse;
import com.sa.event_mng.model.entity.Ticket;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface TicketMapper {
    @Mapping(target = "eventName", source = "ticketType.event.name")
    @Mapping(target = "ticketTypeName", source = "ticketType.name")
    TicketResponse toTicketResponse(Ticket ticket);
}
