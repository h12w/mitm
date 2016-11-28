#!/bin/sh
set -e

# http://pages.cs.wisc.edu/~zmiller/ca-howto/

openssl genrsa -out key 1024
openssl req -new -x509 -days 3650 -key key -out crt
