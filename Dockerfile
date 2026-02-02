FROM openjdk:21
LABEL authors="egorm"

WORKDIR /app
ADD maven/Stroy1Click-AuthService-0.0.1-SNAPSHOT.jar /app/auth.jar
EXPOSE 9070
ENTRYPOINT ["java", "-jar", "auth.jar"]