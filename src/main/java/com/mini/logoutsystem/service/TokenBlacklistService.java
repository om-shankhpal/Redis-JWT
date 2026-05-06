package com.mini.logoutsystem.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // 🔥 Store token in Redis (used during logout)
    public void blacklistToken(String token) {
        redisTemplate.opsForValue().set(token, "blacklisted", 10, TimeUnit.MINUTES);
    }

    // 🔥 Check if token exists in Redis
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }
}