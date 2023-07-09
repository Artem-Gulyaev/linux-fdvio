#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

dmesg -c

#########################################

echo "===== Inserting fdvio module."
insmod /modules/fdvio.ko
sleep 1

#########################################

echo "===== Inserting lbrp module."
insmod /modules/loopback_rpmsg_proc.ko
sleep 1

#########################################

echo "===== @@@@@@@@@ PLATFORM @@@@@@@@@@@."
ls -alR /sys/bus/platform
echo "===== @@@@@@@@@@@@@@@@@@@@."
echo "===== @@@@@@@@@ RPMSG @@@@@@@@@@@."
ls -alR /sys/bus/rpmsg
echo "===== @@@@@@@@@@@@@@@@@@@@."

#########################################

echo "===== Removing lbrp module."
rmmod  loopback_rpmsg_proc
sleep 1

#########################################

echo "===== Removing fdvio module."
rmmod  fdvio
sleep 1


