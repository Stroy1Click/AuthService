package ru.stroy1click.auth.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import ru.stroy1click.auth.service.RefreshTokenService;

@Slf4j
@Component
@RequiredArgsConstructor
public class ExpiredRefreshTokensHandler {

    private final RefreshTokenService refreshTokenService;

    @Scheduled(fixedDelay = 1000)
    public void handle(){
        this.refreshTokenService.deleteAllExpiredTokens();
    }
}
