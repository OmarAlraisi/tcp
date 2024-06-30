#!/bin/bash
cargo b --release
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi;

sudo setcap cap_net_admin=eip ./target/release/rust_tcp
MY_IP=192.168.1.1 ./target/release/rust_tcp &
pid=$!
sudo ip a add 192.168.1.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
