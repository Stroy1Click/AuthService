FROM eclipse-temurin:21-jre-alpine
LABEL authors="egorm"

WORKDIR /app
COPY target/auth-service-0.0.1-SNAPSHOT.jar /app/auth.jar
EXPOSE 9070
ENTRYPOINT ["java", "-jar", "auth.jar"]