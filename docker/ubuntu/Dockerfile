# Ubuntu 2204 Docker image made to be used with ConTackGen
# Docker build command: docker build -t fersuy/contackgen-ubuntu2204:1.1.0 .
# Docker run command: docker run --rm --name contackgen-ubuntu  fersuy/contackgen-ubuntu2204:1.1.0
FROM ubuntu:22.04

# Install dependencies (tshark, nginx)
RUN apt-get update && apt-get install -y tshark nginx

# Set the working directory
WORKDIR /app

# Copy the payload
COPY payload.sh .

# Make the payload executable
RUN chmod +x payload.sh

# Set the entrypoint
ENTRYPOINT ["nginx", "-g", "daemon off;"]