package com.omm.chat.repository;

import com.omm.chat.model.entity.ChatRoom;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.util.Map;

@Repository
@RequiredArgsConstructor
public class ChatRepository {
    private static final String ROOMS = "Rooms";
    private final RedisTemplate redisTemplate;
    private HashOperations<String, String, ChatRoom> opsHashChatRoom;

    @PostConstruct
    private void init() {
        opsHashChatRoom = redisTemplate.opsForHash();
    }

    /**
     * 채팅방 CREATE
     * @param chatRoom
     */
    public void createRoom(ChatRoom chatRoom) {
        opsHashChatRoom.put(ROOMS, chatRoom.getId(), chatRoom);
    }

    public ChatRoom getRoom(String roomId) {
        return opsHashChatRoom.get(ROOMS, roomId);
    }

    public Map<String, ChatRoom> getRooms() {
        return opsHashChatRoom.entries(ROOMS);
    }
}
