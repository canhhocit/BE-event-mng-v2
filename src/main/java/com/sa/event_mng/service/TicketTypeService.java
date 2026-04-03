package com.sa.event_mng.service;

import com.sa.event_mng.dto.request.TicketTypeRequest;
import com.sa.event_mng.dto.response.TicketTypeResponse;
import com.sa.event_mng.exception.AppException;
import com.sa.event_mng.exception.ErrorCode;
import com.sa.event_mng.mapper.TicketTypeMapper;
import com.sa.event_mng.model.entity.Event;
import com.sa.event_mng.model.entity.TicketType;
import com.sa.event_mng.repository.EventRepository;
import com.sa.event_mng.repository.TicketTypeRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class TicketTypeService {

        TicketTypeRepository ticketTypeRepository;
        EventRepository eventRepository;
        TicketTypeMapper ticketTypeMapper;

        @PreAuthorize("hasRole('ORGANIZER') or hasRole('ADMIN')")
        public TicketTypeResponse create(TicketTypeRequest request) {
                Event event = eventRepository.findById(request.getEventId())
                                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

                // Security check
                String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
                if (!event.getOrganizer().getUsername().equals(currentUsername) &&
                                !SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream()
                                                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                        throw new AppException(ErrorCode.UNAUTHORIZED);
                }

                TicketType ticketType = TicketType.builder()
                                .event(event)
                                .name(request.getName())
                                .price(request.getPrice())
                                .totalQuantity(request.getTotalQuantity())
                                .remainingQuantity(request.getTotalQuantity())
                                .description(request.getDescription())
                                .build();

                return ticketTypeMapper.toTicketTypeResponse(ticketTypeRepository.save(ticketType));
        }

        public List<TicketTypeResponse> getByEvent(Long eventId) {
                return ticketTypeRepository.findByEventId(eventId).stream()
                                .map(ticketTypeMapper::toTicketTypeResponse)
                                .toList();
        }

}
