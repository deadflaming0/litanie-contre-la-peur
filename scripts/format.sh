#!/usr/bin/env sh

clj -Tcljfmt fix "{:sort-ns-references? true}"
