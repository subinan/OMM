package com.omm.security;

import com.omm.exception.CustomException;
import com.omm.member.model.dto.AuthDto;
import com.omm.member.service.CustomUserDetailsService;
import com.omm.member.service.DidService;
import com.omm.util.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

/**
 * 일반 멤버: 패스워드 없이 vpJwt를 검증 서버에 확인 후 로그인
 */
@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final DidService didService;

    /**
     * UserDetailsService 분기를 위해 authenticate 오버라이딩
     *
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        String username = authentication.getName();
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
        AuthDto authDto = AuthDto.builder()
                .holderDid(authentication.getPrincipal().toString())
                .vpJwt(authentication.getCredentials().toString())
                .build();

        if (!didService.loginAuth(authDto)) {
            throw new CustomException(ErrorCode.FAIL_TO_LOGIN);
        }

        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(), userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(DidAuthenticationToken.class);
    }

}
