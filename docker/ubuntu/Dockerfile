# Ubuntu 2204 Docker image made to be used with ConTackGen
# Docker build command: docker build -t fersuy/contackgen-ubuntu:22.04 .
# Docker run command: docker run --rm --name contackgen-ubuntu  fersuy/contackgen-ubuntu:22.04
FROM ubuntu:22.04

# Install dependencies (tshark)
RUN apt-get update && apt-get install -y tshark

# Set the working directory
WORKDIR /app

# Copy entrypoint script
COPY entrypoint.sh .

# Make entrypoint script executable
RUN chmod +x entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["./entrypoint.sh"]
