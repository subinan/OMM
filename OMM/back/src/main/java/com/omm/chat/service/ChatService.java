package com.omm.chat.service;

import com.omm.chat.model.dto.ChatRoomDto;
import com.omm.chat.model.dto.request.CreateRoomRequestDto;
import com.omm.chat.model.entity.ChatRoom;
import com.omm.chat.repository.ChatRepository;
import com.omm.exception.CustomException;
import com.omm.model.entity.Member;
import com.omm.repository.MemberRepository;
import com.omm.util.SecurityUtil;
import com.omm.util.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ChatService {
    private final ChatRepository chatRepository;
    private final MemberRepository memberRepository;

    /**
     * Rooms Topic 반환
     * @return
     */
    public ChannelTopic getRoomTopic() {
        return chatRepository.getRoomTopic();
    }

    /**
     * 채팅방 생성
     * @param createRoomRequestDto
     * @return
     */
    public ChatRoom createRoom(CreateRoomRequestDto createRoomRequestDto) {
        Long senderId = createRoomRequestDto.getSenderId();
        Set<Long> userIds = new HashSet<>();
        /*
            TODO: 현재 memberId로 수정
         */
        userIds.add(1000L);
        userIds.add(senderId);
        ChatRoom chatRoom = new ChatRoom(userIds);
        chatRepository.createRoom(chatRoom);
        return chatRoom;
    }

    public List<ChatRoomDto> getRooms() {
        Member myInfo = getMember();
        Map<String, ChatRoom> rooms = chatRepository.getRooms();
        List<ChatRoomDto> myRooms = new ArrayList<>();
        for(Map.Entry<String, ChatRoom> entrySet : rooms.entrySet()) {
            ChatRoom room = entrySet.getValue();
            if(room.isMyRoom(myInfo.getId())) {
                myRooms.add(ChatRoomDto.builder()
                                .id(room.getId())
                                .content(room.getContent())
                                .msgs(room.getMsgs())
                                .lastReadIndex(room.getLastReadIndex())
                                .userIds(room.getUserIds())
                                .build());
            }
        }

        return myRooms;
    }

    public Member getMember() {
        String didAddress = SecurityUtil.getCurrentDidAddress().get();
        return memberRepository.findByDidAddress(didAddress).orElseThrow(() -> {
            throw new CustomException(ErrorCode.CANNOT_AUTHORIZE_MEMBER);
        });
    }
}
