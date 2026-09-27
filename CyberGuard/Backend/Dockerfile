FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y g++ libcurl4-openssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY cyberguard.cpp .

RUN g++ cyberguard.cpp -o cyberguard -lcurl

EXPOSE 8080

CMD ["./cyberguard"]