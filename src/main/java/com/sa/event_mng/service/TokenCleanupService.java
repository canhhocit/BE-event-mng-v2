package com.sa.event_mng.service;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.sa.event_mng.repository.InvalidatedTokenRepository;

import java.util.Date;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class TokenCleanupService {

    InvalidatedTokenRepository invalidatedTokenRepository;

    // 2h
    @Scheduled(fixedRate = 7200000)
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("CLEANUP: Starting to clear expired tokens from blacklist...");
        invalidatedTokenRepository.deleteByExpiryTimeBefore(new Date());
        log.info("CLEANUP: Expired tokens cleared.");
    }
}
