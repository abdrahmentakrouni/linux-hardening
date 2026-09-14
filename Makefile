.PHONY: lint test test-ubuntu test-debian test-rocky help

help:
	@echo "linux-hardening — development helpers"
	@echo "  make lint          run shellcheck on all shell files"
	@echo "  make test          run the docker test suite on all distros"
	@echo "  make test-ubuntu   run the test suite on ubuntu 24.04 only"
	@echo "  make test-debian   run the test suite on debian 12 only"
	@echo "  make test-rocky    run the test suite on rocky 9 only"

lint:
	shellcheck -x harden.sh lib/*.sh tests/*.sh

test: test-ubuntu test-debian test-rocky

test-ubuntu:
	docker build -f tests/Dockerfile.ubuntu -t hardening:ubuntu .
	docker run --rm hardening:ubuntu

test-debian:
	docker build -f tests/Dockerfile.debian -t hardening:debian .
	docker run --rm hardening:debian

test-rocky:
	docker build -f tests/Dockerfile.rocky -t hardening:rocky .
	docker run --rm hardening:rocky
