ifeq ($(origin VERSION), undefined)
  VERSION=$(git rev-parse --short HEAD)
endif
TAG=$(VERSION)
ifeq ($(TAG), )
	TAG=latest
endif
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
REPOPATH = kismatic/kubernetes-ldap

build: vendor
	go build -o bin/kubernetes-ldap -ldflags "-X $(REPOPATH).Version=$(VERSION)" ./cmd/kubernetes-ldap.go

test: bin/glide
	go test $(shell ./bin/glide novendor)

install: bin/glide
	go install $(shell ./bin/glide novendor)

vet: bin/glide
	go vet $(shell ./bin/glide novendor)

fmt: bin/glide
	go fmt $(shell ./bin/glide novendor)

run:
	./bin/kubernetes-ldap

container: build
	docker build -t $(REPOPATH):$(TAG) --rm .

ldap:
	$(MAKE) -c ldap_server

ldap-run:
	$(MAKE) -c ldap_server run

ldap-stop:
	$(MAKE) -c ldap_server run

vendor: bin/glide
	./bin/glide install

bin/glide:
	@echo "Downloading glide"
	mkdir -p bin
	curl -L https://github.com/Masterminds/glide/releases/download/0.10.2/glide-0.10.2-$(GOOS)-$(GOARCH).tar.gz | tar -xz -C bin
	mv bin/$(GOOS)-$(GOARCH)/glide bin/glide
	rm -r bin/$(GOOS)-$(GOARCH)
