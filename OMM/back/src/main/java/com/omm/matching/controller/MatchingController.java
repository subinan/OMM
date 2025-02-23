package com.omm.matching.controller;

import com.omm.alert.service.AlertPublishService;
import com.omm.matching.model.dto.request.CreateNotificationRequestDto;
import com.omm.matching.model.dto.request.DeleteNotificationRequestDto;
import com.omm.matching.model.dto.response.GetNotificationsResponseDto;
import com.omm.matching.model.dto.response.NotificationResponseDto;
import com.omm.matching.model.entity.Notification;
import com.omm.matching.service.MatchingService;
import com.omm.matching.service.NotificationPublisherService;
import com.omm.model.entity.Member;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class MatchingController {
    private final MatchingService matchingService;
    private final NotificationPublisherService publisherService;
    private final AlertPublishService alertPublishService;

    /**
     * 알림 생성
     * @param createNotificationRequestDto
     */
    @MessageMapping("/matching/noti")
    public void createNotification(StompHeaderAccessor accessor, CreateNotificationRequestDto createNotificationRequestDto) {
        String user = accessor.getUser().getName();
        Notification notification = matchingService.createNotification(createNotificationRequestDto.getReceiverId(), user);
        String receiverAddr = matchingService.getReceiverAddr(createNotificationRequestDto.getReceiverId());
        NotificationResponseDto notificationResponseDto = matchingService.getNotificationResponseDto(notification);
        publisherService.publishNotification(receiverAddr, notificationResponseDto);

        Member receiver = matchingService.getMember(receiverAddr);
        alertPublishService.publishNotiAlert(receiver);
    }

    /**
     * 알림 목록 조회
     * @return
     */
    @GetMapping("/matching/noti")
    public ResponseEntity<?> getNotifications() {
        System.out.println("내 알림 찾으러 컨트롤러 왔다");
        List<NotificationResponseDto> notifications = matchingService.getNotifications();
        return new ResponseEntity<>(new GetNotificationsResponseDto(notifications), HttpStatus.OK);
    }

    /**
     * 알림 삭제
     * @param deleteNotificationRequestDto
     * @return
     */
    @DeleteMapping("/matching/noti")
    public ResponseEntity<?> deleteNotification(@RequestBody DeleteNotificationRequestDto deleteNotificationRequestDto) {
        matchingService.deleteNotification(deleteNotificationRequestDto);
        Member myInfo = matchingService.getMember();
        alertPublishService.publishNotiAlert(myInfo);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
