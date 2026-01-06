FROM alpine:latest

COPY seulogin /usr/bin/seulogin
COPY config_example.toml /etc/seulogin/config.toml

ENTRYPOINT ["seulogin", "cron", "/etc/seulogin/config.toml"]