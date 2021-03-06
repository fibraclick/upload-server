#!/bin/bash
set -e

# Log into AWS ECR
echo $DOCKER_REGISTRY_TOKEN | docker login --username AWS --password-stdin $DOCKER_REGISTRY_NAME

cd /home/deploy/docker/fibraclick-upload-server
echo DOCKER_TAG=$DOCKER_TAG > .env
echo HOSTNAME=$HOSTNAME >> .env
docker-compose -f docker-compose.yml pull
docker-compose -f docker-compose.yml -p $CONTAINER_NAME up -d --force-recreate --remove-orphans
exit
