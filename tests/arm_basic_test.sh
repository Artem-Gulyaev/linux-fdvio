#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

insmod /modules/loopback_rpmsg_proc.ko
insmod /modules/fdvio.ko
insmod /modules/iccom.ko
insmod /modules/iccom_socket_if.ko
sleep 1

LBRP_DEV="lbrp.1"
RPMSG_SERVICE_NAME="fdvio"
LBRP_REMOTE_EPT_ADDR="5432"

echo "===== LBRP DEVICE:"
ls -al /sys/devices/platform/${LBRP_DEV}

echo "===== RPMSG DEVICES:"
ls -al /sys/bus/rpmsg

sleep 1

echo "===== Creating remote endpoint for 'fdvio' service:"
echo -n "${RPMSG_SERVICE_NAME} ${LBRP_REMOTE_EPT_ADDR}" \
        > /sys/devices/platform/${LBRP_DEV}/create_ept


############## In production this will be the Udev rule ##############

# will be triggered when the "fdvio" service appears in rpmsg

ICCOM_DEV="iccom.0"
ICCOM_SKIF_DEV="iccom_socket_if.0"
FDVIO_PL_DEV="fdvio_pd.1"
ICCOM_SKIF_SOCKETS_FAMILY="22"

echo "===== Creating ICCom device:"
echo -n " " > "/sys/class/iccom/create_iccom"

echo "===== PLATFORM DEVICES:"
ls -al /sys/bus/platform/devices

echo "===== Binding ICCom to Fdvio device:"
echo -n "${FDVIO_PL_DEV}" > "/sys/devices/platform/${ICCOM_DEV}/transport"

echo "===== Creating ICComSkif device:"
echo -n " " > "/sys/class/iccom_socket_if/create_device"

echo "===== PLATFORM DEVICES:"
ls -al /sys/bus/platform/devices

echo "===== Binding ICComSkif to ICCom device:"
echo -n "${ICCOM_SKIF_SOCKETS_FAMILY}" \
        > "/sys/devices/platform/${ICCOM_SKIF_DEV}/protocol_family"
echo -n "${ICCOM_DEV}" > "/sys/devices/platform/${ICCOM_SKIF_DEV}/iccom_dev"

###########################  EOF Udev rule ############################

# Now shutdown simulation #

echo "===== Removing ICComSkif device:"
echo -n "${ICCOM_SKIF_DEV}" > "/sys/class/iccom_socket_if/delete_device"

echo "===== Removing ICCom device:"
echo -n "${ICCOM_DEV}" > "/sys/class/iccom/delete_iccom"

echo "===== Removing remote endpoint for 'fdvio' service:"
echo -n "${RPMSG_SERVICE_NAME} ${LBRP_REMOTE_EPT_ADDR}" \
        > /sys/devices/platform/${LBRP_DEV}/remove_ept

