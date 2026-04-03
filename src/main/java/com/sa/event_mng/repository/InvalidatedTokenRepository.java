package com.sa.event_mng.repository;

import com.sa.event_mng.model.entity.InvalidatedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Date;

@Repository
public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, String> {
    void deleteByExpiryTimeBefore(Date date);
}
