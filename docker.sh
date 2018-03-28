#!/bin/bash
set -e

cd /home

# Docker Install
openssl s_client -connect download.docker.com:443
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu \xenial \stable"
sudo apt-get update
apt-cache policy docker-ce
sudo apt-get install -y docker-ce
sudo systemctl status docker


# Install docker container
docker run --name mynginx1 -P -d nginx

# curl http://localhost:80


# Docker file
cat > nginx.txt <<EOF
RUN apt-get update && apt-get install -y nginx

EOF 

# nginx_config
cat > nginx.conf <<EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
    # multi_accept on;
}

http {

    # Basic Settings
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    # server_tokens off;
    
    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Settings
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;
    
    # Logging Settings
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Settings
    
    gzip on;
    gzip_disable "msie6";
    
    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Virtual Host Configs
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

EOF 
