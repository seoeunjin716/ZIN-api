# ============================================
# 모놀리식 구조 Dockerfile
# ============================================

# ============================================
# 1단계: 빌드 스테이지
# ============================================
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app

# Gradle 래퍼 및 설정 파일 복사
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .

# 소스 코드 복사
COPY src src

# 빌드 실행
RUN chmod +x gradlew && ./gradlew build -x test

# ============================================
# 2단계: 실행 스테이지
# ============================================
FROM eclipse-temurin:21-jre
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/build/libs/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]