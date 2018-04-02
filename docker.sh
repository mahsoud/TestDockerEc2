#!/bin/bash
set -e

cd /home

# Docker Install
sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y docker-ce
apt policy docker-ce

# Adding current user to docker group. Requires restart.
# sudo usermod -a -G docker $USER

# Launch NGINX container
sudo docker run -p 80:80 --name mynginx1 -P -d nginx

# Confirm container is up
curl http://localhost:80
