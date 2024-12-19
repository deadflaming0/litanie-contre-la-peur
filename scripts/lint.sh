#!/usr/bin/env sh

clj -M:clj-kondo --lint src
clj -M:clj-kondo --lint test
