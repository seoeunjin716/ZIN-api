package com.seoeunjin.api.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 로컬 프론트엔드(Next.js)에서 백엔드로 fetch 호출 시 CORS 차단(TypeError: Failed to fetch)을
 * 방지합니다.
 *
 * - 허용 오리진: localhost(3000/4000), 127.0.0.1(3000/4000), 프로덕션 도메인(seoeunjin.com)
 * - 쿠키 기반 플로우도 가능하도록 allowCredentials(true)
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(@NonNull CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(
                        "http://localhost:3000",
                        "http://127.0.0.1:3000",
                        "http://localhost:4000",
                        "http://127.0.0.1:4000",
                        "https://seoeunjin.com",
                        "https://www.seoeunjin.com")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .exposedHeaders("Set-Cookie")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
