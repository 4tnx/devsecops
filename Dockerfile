# Use a specific valid OpenJDK 17 slim image
FROM eclipse-temurin:17-jdk

# Set working directory
WORKDIR /app

# Copy built jar into container
COPY target/*.jar app.jar

# Expose port your app runs on
EXPOSE 8080

# Run the app
ENTRYPOINT ["java", "-jar", "app.jar"]