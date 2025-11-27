# Use Tomcat with Java 17 or 21 (recommended modern)
FROM tomcat:10-jdk21

LABEL Project="devsecops"
LABEL Author="4tnx"

# Clean default webapps
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy WAR (from Jenkins pipeline output)
COPY target/*.war /usr/local/tomcat/webapps/ROOT.war

# Expose port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl --silent --fail http://localhost:8080/ || exit 1

# Working directory
WORKDIR /usr/local/tomcat/

# Start Tomcat
CMD ["catalina.sh", "run"]
