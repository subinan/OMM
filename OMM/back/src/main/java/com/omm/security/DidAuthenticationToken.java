package com.omm.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class DidAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public DidAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }
}
