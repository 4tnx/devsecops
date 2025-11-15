FROM tomcat:10-jdk21
LABEL "Project"="devsecops"
LABEL "Author"="4tnx"

RUN rm -rf /usr/local/tomcat/webapps/*
COPY target/vprofile-v2.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080
CMD ["catalina.sh", "run"]
WORKDIR /usr/local/tomcat/
VOLUME /usr/local/tomcat/webapps
# Use Tomcat base
FROM tomcat:9.0-jdk11-openjdk

# Remove default webapps (optional)
RUN rm -rf /usr/local/tomcat/webapps/*

# Copy WAR to Tomcat webapps dir (adapt path/name if different)
COPY target/*.war /usr/local/tomcat/webapps/ROOT.war

# Expose port 8080 and define healthcheck
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl --silent --fail http://localhost:8080/ || exit 1

# Start Tomcat (image default CMD already does this)
