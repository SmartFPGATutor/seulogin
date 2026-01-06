#! /bin/sh

mkdir -p /etc/seulogin

mkdir -p /var/log/seulogin

/usr/bin/seulogin gen /etc/seulogin/example.toml
/usr/bin/seulogin gen /etc/seulogin/example.json