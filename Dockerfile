# Builds an image for use running this service inside the cluster.
FROM ubuntu:xenial

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY bin/kubernetes-ldap /bin/kubernetes-ldap

EXPOSE 4000

ENTRYPOINT [ "/bin/kubernetes-ldap" ]
