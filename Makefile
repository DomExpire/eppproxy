.PHONY: help
help:
	@echo "Make build|start|stop|log"

.PHONY: install
install:
	@curl -fsSL https://get.docker.com -o get-docker.sh
	@sudo sh get-docker.sh

.PHONY: build
build:
	@docker build . -f docker/Dockerfile -t eppproxy

.PHONY: start
start:
	@docker run --rm -it -d --name=eppproxy --env-file envfile --mount type=bind,source=${PWD}/certs,target=/app/certs --mount type=bind,source=${PWD}/python/log,target=/app/log -p 700:700 --network web eppproxy:latest

.PHONY: stop
stop:
	@docker stop eppproxy

.PHONY: retstart
restart:
	@make stop
	@make start

.PHONY: log
log:
	@tail -f -n 50 python/log/proxy.log

