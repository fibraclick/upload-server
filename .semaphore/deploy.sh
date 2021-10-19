#!/bin/bash
set -e

# Log into AWS ECR
echo $DOCKER_REGISTRY_TOKEN | docker login --username AWS --password-stdin $DOCKER_REGISTRY_NAME

cd /home/deploy/docker/fibraclick-upload-server
if grep -q -F 'DOCKER_TAG=' .env ; then sed -i 's/DOCKER_TAG=.*/DOCKER_TAG=$DOCKER_TAG/g' .env; else echo "DOCKER_TAG=$DOCKER_TAG" >> .env; fi
docker-compose -f docker-compose.yml pull
docker-compose -f docker-compose.yml -p $CONTAINER_NAME up -d --force-recreate --remove-orphans
exit
