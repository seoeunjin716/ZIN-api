package com.seoeunjin.api.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RedisStartupCheck implements CommandLineRunner {

    private final StringRedisTemplate redisTemplate;

    public RedisStartupCheck(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void run(String... args) {
        try {
            // Data Browser에서 확인할 수 있도록 TTL을 충분히 길게 설정
            String key = "health:startup";
            redisTemplate.opsForValue().set(key, "ok", 1, TimeUnit.DAYS);
            String val = redisTemplate.opsForValue().get(key);
            System.out.println("[Redis] startup check OK (set/get): " + val + " (ttl=1d)");
        } catch (Exception e) {
            System.err.println("[Redis] startup check FAILED: " + e.getMessage());
        }
    }
}


