#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

dmesg -c

#########################################

echo "===== Inserting lbrp module."
insmod /modules/loopback_rpmsg_proc.ko
sleep 1

#########################################

echo "===== LBRP"
ls -aR /sys/devices/platform/lbrp.1

echo "===== RPMSG"
ls -aR /sys/bus/rpmsg

echo "===== PLATFORM DEV"
ls -aR /sys/devices/platform

sleep 1



echo "===== LBRP: creating remote endpoint."
echo -n "fdvio 5432" > /sys/devices/platform/lbrp.1/create_ept

echo "===== RPMSG"
ls -aR /sys/bus/rpmsg

echo "===== PLATFORM DEV"
ls -aR /sys/devices/platform

echo "===== LBRP DEV"
ls -aR /sys/devices/platform/lbrp.1


echo "===== LBRP: writing data to remote endpoint."
echo -n -e "\x00\x40\x00\x00aaabbb" > /sys/devices/platform/lbrp.1/fdvio/ept_5432

#########################################

echo "===== Inserting fdvio module."
insmod /modules/fdvio.ko
sleep 1

echo "===== PLATFORM DEV"
ls -aR /sys/devices/platform

echo "===== LBRP DEV"
ls -aR /sys/devices/platform/lbrp.1

#########################################

echo "===== LBRP: writing data to remote endpoint AGAIN."
echo -n -e "\x00\x04\x00\x00aaabbb" > /sys/devices/platform/lbrp.1/fdvio/ept_5432

#########################################

echo "===== Removing fdvio module."
rmmod  fdvio
sleep 1

#########################################

echo "===== Removing lbrp module."
rmmod  loopback_rpmsg_proc
sleep 1

