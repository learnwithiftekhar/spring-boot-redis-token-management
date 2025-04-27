package com.learnwithiftekhar.redissessionmanagement.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@AllArgsConstructor
public class TokenPair {
    private String accessToken;
    private String refreshToken;
    private long accessTokenExpirationMs;
    private long refreshTokenExpirationMs;
}
