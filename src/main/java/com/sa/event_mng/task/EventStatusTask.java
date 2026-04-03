package com.sa.event_mng.task;

import com.sa.event_mng.model.entity.Event;
import com.sa.event_mng.model.enums.EventStatus;
import com.sa.event_mng.repository.EventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class EventStatusTask {

    private final EventRepository eventRepository;

    /**
     * Tự động cập nhật trạng thái sự kiện mỗi phút.
     */
    @Scheduled(fixedRate = 60000)
    @Transactional
    public void autoUpdateEventStatus() {
        LocalDateTime now = LocalDateTime.now();
        
        // Chỉ quét các sự kiện có khả năng thay đổi trạng thái tự động
        List<EventStatus> activeStatuses = Arrays.asList(
                EventStatus.UPCOMING,
                EventStatus.OPENING,
                EventStatus.CLOSED
        );

        List<Event> events = eventRepository.findByStatusIn(activeStatuses);
        
        for (Event event : events) {
            EventStatus oldStatus = event.getStatus();
            EventStatus newStatus = determineStatus(event, now);
            
            if (oldStatus != newStatus) {
                event.setStatus(newStatus);
                eventRepository.save(event);
                log.info("Event ID {}: Auto-updated status from {} to {}", event.getId(), oldStatus, newStatus);
            }
        }
    }

    private EventStatus determineStatus(Event event, LocalDateTime now) {
        // quá end_time COMPLETED
        if (event.getEndTime() != null && now.isAfter(event.getEndTime())) {
            return EventStatus.COMPLETED;
        }
        
        // quá thời gian bắt đầu sự kiện (mà chưa có endTime) -> COMPLETED ( coi như đã diễn ra)
        if (event.getEndTime() == null && event.getStartTime() != null && now.isAfter(event.getStartTime())) {
            return EventStatus.COMPLETED;
        }

        // Kiểm tra thời gian bán vé
        if (event.getSaleEndDate() != null && now.isAfter(event.getSaleEndDate())) {
            return EventStatus.CLOSED; // Hết hạn bán vé
        }

        if (event.getSaleStartDate() != null && (now.isAfter(event.getSaleStartDate()) || now.isEqual(event.getSaleStartDate()))) {
            return EventStatus.OPENING; // Đang trong thời gian bán vé
        }

        //chưa đến ngày bán vé
        return EventStatus.UPCOMING;
    }
}
