#!/usr/bin/env sh

clj -X:test :reporter kaocha.report/documentation
