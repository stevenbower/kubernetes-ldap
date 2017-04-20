NAME = kubernetes-ldap/openldap-test
VERSION = 0.1.0
RUN_NAME=ldap-server

.PHONY: all build build-nocache

all: build

build:
	docker build -t $(NAME):$(VERSION) --rm .

build-nocache:
	docker build -t $(NAME):$(VERSION) --no-cache --rm .

stop:
	-docker stop $(RUN_NAME)

remove:
	-docker rm $(RUN_NAME)

run: stop remove
	echo "Starting..."
	docker run \
		--name $(RUN_NAME) \
		--detach \
		-p 389:389 \
		-p 636:636 \
		$(NAME):$(VERSION) #--loglevel=debug

run-debug: stop remove
	echo "Starting (debug)..."
	docker run \
		--name $(RUN_NAME) \
		-p 389:389 \
		-p 636:636 \
		$(NAME):$(VERSION) \
		--loglevel=debug

dump:
	ldapsearch -x -b ou=people,dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin dn memberOf
	
