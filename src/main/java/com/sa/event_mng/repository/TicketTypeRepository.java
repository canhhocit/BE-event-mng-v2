package com.sa.event_mng.repository;

import com.sa.event_mng.model.entity.TicketType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface TicketTypeRepository extends JpaRepository<TicketType, Long> {
    List<TicketType> findByEventId(Long eventId);
}
