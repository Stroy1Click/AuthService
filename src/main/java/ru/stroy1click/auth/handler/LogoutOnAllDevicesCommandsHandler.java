package ru.stroy1click.auth.handler;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaHandler;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;
import ru.stroy1click.auth.service.RefreshTokenService;
import ru.stroy1click.common.command.LogoutOnAllDevicesCommand;
import ru.stroy1click.outbox.consumer.entity.ProcessedEvent;
import ru.stroy1click.outbox.consumer.service.ProcessedEventService;

@Slf4j
@Component
@KafkaListener(topics = {"logout-on-all-devices-commands"})
@RequiredArgsConstructor
public class LogoutOnAllDevicesCommandsHandler {

    private final RefreshTokenService refreshTokenService;

    private final ProcessedEventService processedEventService;

    @KafkaHandler
    public void handle(@Header(name = "messageId") byte[] messageIdBytes, @Payload LogoutOnAllDevicesCommand event){
        log.info("handle {}", event);

        //сразу в Long нельзя, так как автоматически не преобразовывается
        Long messageId = Long.valueOf(new String(messageIdBytes));

        if(this.processedEventService.findByMessageId(messageId).isPresent()){
            log.warn("Event with messageId {} already processed. Skipping.", messageId);
            return;
        }

        this.refreshTokenService.deleteAll(event.getEmail());

        this.processedEventService.save(new ProcessedEvent(null, messageId));
    }
}