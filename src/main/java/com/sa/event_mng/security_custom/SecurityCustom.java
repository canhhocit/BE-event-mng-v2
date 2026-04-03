package com.sa.event_mng.security_custom;

import com.sa.event_mng.repository.EventRepository;
import com.sa.event_mng.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("securityCustom")
@RequiredArgsConstructor
public class SecurityCustom {

    private final EventRepository eventRepository;
    private final UserRepository userRepository;

    public boolean isOwner(Long eventId, Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return false;
        }

        String username = authentication.getName();

        return eventRepository.findById(eventId)
                .map(event -> event.getOrganizer() != null
                        && event.getOrganizer().getUsername() != null
                        && event.getOrganizer().getUsername().equals(username))
                .orElse(false);
    }

    public boolean isCurrentUser(Long userId, Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return false;
        }

        String username = authentication.getName();

        return userRepository.findByUsernameAndEnabledTrue(username)
                .map(user -> user.getId() != null && user.getId().equals(userId))
                .orElse(false);
    }
}
