#!/bin/bash

cargo build
cp target/debug/rookie /usr/local/bin/
echo "Rookie has been installed in /usr/local/bin"
