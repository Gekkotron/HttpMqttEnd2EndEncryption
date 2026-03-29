#!/bin/bash

docker compose down
git pull --rebase
docker compose up -d --build