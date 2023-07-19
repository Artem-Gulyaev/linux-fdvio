#!/bin/sh

# Tests the fdvio driver insertion and removal.

set -e

# Create an iccom sysfs channel
#
# $1 iccom device name
# $2 sysfs channel number
create_iccom_sysfs_channel() {
    local iccom_dev=$1
    local channel=$2
    echo "creating iccom channel: ${iccom_dev}:${channel}"
    echo -n c${channel} > /sys/devices/platform/${iccom_dev}/channels_ctl
}

# Set the iccom sysfs channel to read or write
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
set_iccom_sysfs_channel() {
    local iccom_dev=$1
    local channel=$2
    echo "selecting iccom channel: ${iccom_dev}:${channel}"
    echo -n s${channel} > /sys/devices/platform/${iccom_dev}/channels_ctl
}

# Writes message to the given iccom sysfs channel
#
# $1 id of the iccom device
# $2 the destination channel id
# $3 message to send
iccom_send() {
    local iccom_dev=$1
    local channel=$2
    local message=$3
    set_iccom_sysfs_channel ${iccom_dev} ${channel}
    echo "sending data to iccom channel: ${iccom_dev}:${channel}"
    sh -c "echo -n ${message} > /sys/devices/platform/${iccom_dev}/channels_RW"
}

# sends wire data from lbrp
# $1 lbrp device name
# $2 service name
# $3 lbrp ept addr
# $4 dst addr (hex string) of 4 bytes
# $5 data hex string
lbrp_send() {
    local lbrp_device_name=$1
    local service_name=$2
    local src_addr=$3
    local dst_addr_hex_str=$4
    local data_hex_str=$5

    local ept_file="/sys/devices/platform/${lbrp_device_name}/${service_name}/ept_${src_addr}"

    echo "${dst_addr_hex_str}${data_hex_str}" | xxd -r -p > ${ept_file}
}

# reads wire data from lbrp
# $1 lbrp device name
# $2 service name
# $3 lbrp ept addr
lbrp_read() {
    local lbrp_device_name=$1
    local service_name=$2
    local dst_addr=$3

    local ept_file="/sys/devices/platform/${lbrp_device_name}/${service_name}/ept_${dst_addr}"

    cat "${ept_file}" | xxd -p | tr -d '\n' | tr -d ' ' | cut -c 9-
}


# Does the wire full duplex xfer and checks if the
# received data matches expected
#
# $1 iccom device name
# $2 full duplex test device name
# $3 the destination channel id
# $4 the bytearray of the data to send
# $5 bytearray we expect to receive
# $6 lbrp device name
# $7 fdvio service name
# $8 lbrp remote ept addr
check_wire_xfer() {
    local iccom_dev=$1
    local channel=$2
    local send_data=$3
    local exp_rcv_data=$4
    local lbrp_device_name=$5
    local fdvio_service_name=$6
    local lbrp_remote_ept_addr=$7

    echo "check wire level:"
    echo "   * iccom_dev=${iccom_dev}"
    echo "   * channel=${channel}"
    echo "   * send_data=${send_data}"
    echo "   * exp_rcv_data=${exp_rcv_data}"
    echo "   * lbrp_device_name=${lbrp_device_name}"
    echo "   * fdvio_service_name=${fdvio_service_name}"
    echo "   * lbrp_remote_ept_addr=${lbrp_remote_ept_addr}"

    # Set operating Sysfs Channel
    set_iccom_sysfs_channel ${iccom_dev} ${channel}

    # Send the data from lbrp side
    lbrp_send ${lbrp_device_name} ${fdvio_service_name} ${lbrp_remote_ept_addr} 00040000 ${send_data}

    # Receive the data on lbrp side
    local rcv_data=$(lbrp_read ${lbrp_device_name} ${fdvio_service_name} ${lbrp_remote_ept_addr})
 
    if [ "${rcv_data}" != "${exp_rcv_data}" ]
    then
        echo "Expectation failed!"
        echo "Lbrp expected: " ${exp_rcv_data}
        echo "Lbrp received: " ${rcv_data}
        exit 1
    fi
}


######################## TEST EXEC SEQUENCE ##########################

LBRP_DEV="lbrp.1"
RPMSG_SERVICE_NAME="fdvio"
LBRP_REMOTE_EPT_ADDR="5432"
FDVIO_PL_DEV="fdvio_pd0"
ICCOM_DEV="iccom0"
ICCOM_SKIF_DEV="iccomsk0"
ICCOM_SKIF_SOCKETS_FAMILY="22"


echo "== loopback_rpmsg_proc: inserting"
insmod /modules/loopback_rpmsg_proc.ko
echo "== fdvio: inserting"
insmod /modules/fdvio.ko &

echo "===== Creating remote endpoint for 'fdvio' service:"
echo -n "${RPMSG_SERVICE_NAME} ${LBRP_REMOTE_EPT_ADDR}" \
        > /sys/devices/platform/${LBRP_DEV}/create_ept

sleep 1

echo "== iccom: inserting"
insmod /modules/iccom.ko
echo "== iccom_socket_if: inserting"
insmod /modules/iccom_socket_if.ko

echo "== fdvio.arm.dt.lbrp.lbrp_dev_created"
ls -al /sys/devices/platform | grep "${LBRP_DEV}"
echo "fdvio.arm.dt.lbrp.lbrp_dev_created: PASS"

echo "== fdvio.arm.dt.lbrp.fdvio_platform_dev_created"
ls -al /sys/devices/platform | grep "${FDVIO_PL_DEV}"
echo "fdvio.arm.dt.lbrp.fdvio_platform_dev_created: PASS"

############## In production this will be the Udev rule ##############

# will be triggered when the "fdvio" service appears in rpmsg

echo "== fdvio.arm.dt.iccom_dev_created"
ls -al /sys/bus/platform/devices | grep "${ICCOM_DEV}"
echo "fdvio.arm.dt.iccom_dev_created: PASS"

echo "== fdvio.arm.dt.iccom_skif_dev_created"
ls -al /sys/bus/platform/devices | grep "${ICCOM_SKIF_DEV}"
echo "fdvio.arm.dt.iccom_skif_dev_created: PASS"

###########################  EOF Udev rule ############################

iccom_data_exchange_to_transport_with_iccom_data_with_transport_data() {
    echo "== fdvio.arm.dt.udev_stack.min_com"

    local channel="1"
    local lbrp_dev="lbrp"

    create_iccom_sysfs_channel "${ICCOM_DEV}" ${channel}
    iccom_send ${ICCOM_DEV} ${channel} "Who are you?"

    FF="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    local send_data="000001${FF}ffffffffffffffffffffffffffffffffffb8c8b346"
    local exp_data="000001${FF}ffffffffffffffffffffffffffffffffffb8c8b346"

    check_wire_xfer ${ICCOM_DEV} ${channel} ${send_data} \
                    ${exp_data} ${LBRP_DEV} ${RPMSG_SERVICE_NAME} \
                    ${LBRP_REMOTE_EPT_ADDR}

    send_data="d0"
    exp_data="d0"
    check_wire_xfer ${ICCOM_DEV} ${channel} ${send_data} \
                    ${exp_data} ${LBRP_DEV} ${RPMSG_SERVICE_NAME} \
                    ${LBRP_REMOTE_EPT_ADDR}

    send_data="000d02000900814920616d204c756973${FF}ffffffff513d7dd4"
    exp_data="001002000c008157686f2061726520796f753${FF}fff788d44db"
    check_wire_xfer ${ICCOM_DEV} ${channel} ${send_data} \
                    ${exp_data} ${LBRP_DEV} ${RPMSG_SERVICE_NAME} \
                    ${LBRP_REMOTE_EPT_ADDR}

    send_data="d0"
    exp_data="d0"
    check_wire_xfer ${ICCOM_DEV} ${channel} ${send_data} \
                    ${exp_data} ${LBRP_DEV} ${RPMSG_SERVICE_NAME} \
                    ${LBRP_REMOTE_EPT_ADDR}

    echo "fdvio.arm.dt.udev_stack.min_com: PASS"
}

# Small communication test #

iccom_data_exchange_to_transport_with_iccom_data_with_transport_data

# Now shutdown simulation #

echo "===== Removing remote endpoint for 'fdvio' service:"
echo -n "${RPMSG_SERVICE_NAME} ${LBRP_REMOTE_EPT_ADDR}" \
        > /sys/devices/platform/${LBRP_DEV}/remove_ept

echo "fdvio.arm.dt.reached_shutdown: PASS"
