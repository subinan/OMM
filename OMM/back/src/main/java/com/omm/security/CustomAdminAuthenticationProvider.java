package com.omm.security;

import com.omm.exception.CustomException;
import com.omm.member.service.CustomAdminDetailsService;
import com.omm.util.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 관리자 멤버: username과 password로 로그인
 */
@Component
@RequiredArgsConstructor
public class CustomAdminAuthenticationProvider implements AuthenticationProvider {

    private final CustomAdminDetailsService customAdminDetailsService;

    private final PasswordEncoder passwordEncoder;

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
        UserDetails userDetails = customAdminDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(authentication.getCredentials().toString(),
                userDetails.getPassword())) {
            throw new CustomException(ErrorCode.FAIL_TO_LOGIN);
        }

        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(), userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AdminAuthenticationToken.class);
    }

}
