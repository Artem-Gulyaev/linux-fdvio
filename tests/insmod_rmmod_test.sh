#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

dmesg -c

#########################################

echo "===== Inserting lbrp module."
insmod /modules/loopback_rpmsg_proc.ko
sleep 1

#########################################

echo ""
echo ""
echo "===== @@@@@@@@@ LBRP @@@@@@@@@@@."
ls -alR /sys/devices/platform/lbrp.1
echo "===== @@@@@@@@@@@@@@@@@@@@."
sleep 1
echo ""
echo "===== @@@@@@@@@ RPMSG @@@@@@@@@@@."
ls -alR /sys/bus/rpmsg
echo "===== @@@@@@@@@@@@@@@@@@@@."
echo ""
echo ""
sleep 1


#########################################

echo "===== LBRP: creating remote endpoint."
echo -n "fdvio_rpmsg 5432" > /sys/devices/platform/lbrp.1/create_ept

echo "===== @@@@@@@@@ RPMSG @@@@@@@@@@@."
ls -alR /sys/bus/rpmsg
echo "===== @@@@@@@@@@@@@@@@@@@@."
echo ""

echo "===== @@@@@@@@@ LBRP DEV @@@@@@@@@@@."
ls -alR /sys/devices/platform/lbrp.1
echo "===== @@@@@@@@@@@@@@@@@@@@."
echo ""

echo "===== LBRP: writing data to remote endpoint."
echo -n "1122aaabbb" > /sys/devices/platform/lbrp.1/fdvio_rpmsg/ept_5432

#########################################

echo "===== Inserting fdvio module."
insmod /modules/fdvio.ko
sleep 1

#########################################

echo "===== Removing fdvio module."
rmmod  fdvio
sleep 1

#########################################

echo "===== Removing lbrp module."
rmmod  loopback_rpmsg_proc
sleep 1

