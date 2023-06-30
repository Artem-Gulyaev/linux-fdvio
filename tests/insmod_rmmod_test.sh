#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

insmod /modules/fdvio.ko
sleep 1
dmesg | grep "docker_build_image_test_driver_init"
echo "bosch-linux-ext-modules-build-test.insmod: PASS"

rmmod  fdvio
sleep 1
dmesg | grep "docker_build_image_test_driver_exit"
echo "bosch-linux-ext-modules-build-test.rmmod: PASS"


