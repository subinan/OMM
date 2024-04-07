package com.omm.member.service;

import com.omm.exception.CustomException;
import com.omm.jwt.TokenProvider;
import com.omm.security.AdminAuthenticationToken;
import com.omm.security.DidAuthenticationToken;
import com.omm.util.error.ErrorCode;

import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final RedisTemplate redisTemplate;

    private final TokenProvider tokenProvider;

    private final AuthenticationManager authenticationManager;

    public String authenticate(String holderDid, String vpJwt){

        DidAuthenticationToken authenticationToken =
                new DidAuthenticationToken(holderDid, vpJwt);

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return tokenProvider.createToken(authentication);
    }

    public String adminAuthenticate(String username, String password){

        AdminAuthenticationToken authenticationToken =
                new AdminAuthenticationToken(username, password);

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        return tokenProvider.createToken(authentication);
    }


    @Transactional
    public void logout(String jwt){
        if (!tokenProvider.validateToken(jwt)){
            throw new CustomException(ErrorCode.INVALID_AUTH_TOKEN);
        }

        Long expiration = tokenProvider.getExpiration(jwt);
        redisTemplate.opsForValue().set(jwt, "logout", expiration, TimeUnit.MILLISECONDS);
    }

}
