import subprocess
import zlib
from time import sleep
import errno
import os
import string
import random

import fdvio_common as fdvio_common

def lbrp_dev_name():
    return "lbrp.1"

# inserts the lbrp module
def insert_lbrp_module():
    print("Inserting lbrp module.")

    fdvio_common.execute_command("insmod /modules/loopback_rpmsg_proc.ko")
    sleep(0.2)

# inserts the fdvio module
def insert_fdvio_module():
    print("Inserting fdvio module.")

    fdvio_common.execute_command("insmod /modules/fdvio.ko")
    sleep(0.2)

# inserts the iccom module
def insert_iccom_module():
    print("Inserting iccom module.")

    fdvio_common.execute_command("insmod /modules/iccom.ko")
    sleep(0.2)

# removes the lbrp module
def remove_lbrp_module():
    print("Removing lbrp module.")
    fdvio_common.execute_command("rmmod loopback_rpmsg_proc")
    sleep(0.2)

# removes the fdvio module
def remove_fdvio_module():
    print("Removing fdvio module.")
    fdvio_common.execute_command("rmmod fdvio")
    sleep(0.2)

# removes the iccom module
def remove_iccom_module():
    print("Removing iccom module.")
    fdvio_common.execute_command("rmmod iccom")
    sleep(0.2)

# RETURNS: if the lbrp dev exists
def lbrp_dev_exists():
    return os.path.exists("/sys/devices/platform/" + lbrp_dev_name())

# creates the "remote" endpoint (and service if needed)
# EXAMPLE:
#       to create the endpoint with addr 1234 on "fdvio" service
#       echo -n -e "fdvio 1234" > CREATE_EPT_FILE
def lbrp_create_remote_ept(service_name, addr):

    print("Creating remote ept: %s:%d" % (service_name, addr))

    create_ept_file = "/sys/devices/platform/" + lbrp_dev_name() + "/create_ept"
    fdvio_common.write_sysfs_file(create_ept_file
                                  , (service_name + " " + str(addr)).encode('utf-8')
                                  , None, True)
    sleep(0.2)

# removes the "remote" endpoint (and service if needed)
# EXAMPLE:
#       to remove the endpoint with addr 1234 on "fdvio" service
#       echo -n -e "fdvio 1234" > REMOVE_EPT_FILE
def lbrp_remove_remote_ept(service_name, addr):

    print("Removing remote ept: %s:%d" % (service_name, addr))

    remove_ept_file = "/sys/devices/platform/" + lbrp_dev_name() + "/remove_ept"
    fdvio_common.write_sysfs_file(remove_ept_file
                                  , (service_name + " " + str(addr)).encode('utf-8')
                                  , None, True)
    sleep(0.2)

# Throws if remote endpoint doesn't exist
def lbrp_ensure_remote_ept(service_name, addr):

    ept_file = ("/sys/devices/platform/" + lbrp_dev_name() + "/"
                + service_name + "/ept_" + str(addr))

    if not os.path.exists(ept_file):
        raise Exception("Expected remote ept exist, while it is not: "
                        + ept_file);

# Throws if remote endpoint exist
def lbrp_ensure_no_remote_ept(service_name, addr):

    ept_file = ("/sys/devices/platform/" + lbrp_dev_name() + "/"
                + service_name + "/ept_" + str(addr))

    if os.path.exists(ept_file):
        raise Exception("Expected remote ept to not exist, while it is: "
                        + ept_file);

# Sends the data from "remote" service to the local service
# @data bytearray or comprable
# EXAMPLE:
#       to send the "qwerty" string to 0x400 endpoint:
#       echo -n -e "\x00\x04\x00\x00qwerty" > SRC_ENDPOINT_FILE
def lbrp_send_data(service_name, src_addr, dst_addr, data):

    print("->  %s:%d => %d:  %s"
          % (service_name, src_addr, dst_addr
             , ''.join('{:02x}'.format(x) for x in data)))

    ept_file = ("/sys/devices/platform/" + lbrp_dev_name()
                + "/" + str(service_name)
                + "/ept_" + str(src_addr))

    output_data = dst_addr.to_bytes(4, 'big') + data;

    fdvio_common.write_sysfs_file(ept_file, output_data, None, True)
    sleep(0.2)


# Reads the data which came to the "remote" endpoint with addr @dst_addr.
#
# RETURNS:
#       (src_addr, data)
def lbrp_read_data(service_name, dst_addr):

    print("Reading the data at %s:%d" % (service_name, dst_addr))

    ept_file = ("/sys/devices/platform/" + lbrp_dev_name()
                + "/" + str(service_name)
                + "/ept_" + str(dst_addr))

    raw_data = fdvio_common.read_sysfs_file(ept_file, None, True)

    ADDR_SIZE = 4

    if (len(raw_data) == 0):
        return (None, bytearray()) 

    if (len(raw_data) < ADDR_SIZE):
        raise RuntimeError("Lbrp data read error: \n"
                           "    file: %s \n"
                           "    error: data size must be >= %d\n"
                           "          actual data size: %d\n"
                           % (ept_file, ADDR_SIZE, len(raw_data)))

    src_addr = int.from_bytes(raw_data[0:ADDR_SIZE], 'big')

    return (src_addr, raw_data[ADDR_SIZE:])


#---------------------------- ICCOM ----------------------------------#

# NOTE: TODO: ICCom section is taken from the ICCom but should be
#       used directly from there


# Create an iccom devices and propagate
# the error expectations
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_device(err_expectation):
    file = "/sys/class/iccom/create_iccom"
    command = " "
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Delete an iccom devices and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_device(iccom_dev, err_expectation):
    file = "/sys/class/iccom/delete_iccom"
    command = "%s" % (iccom_dev)
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Create an full duplex test transport device and propagate
# the error expectations
#
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_fd_test_transport_device(err_expectation):
    file = "/sys/class/fd_test_transport/create_transport"
    command = " "
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Delete an full duplex test transport device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_fd_test_transport_device(transport_dev, err_expectation):
    file = "/sys/class/fd_test_transport/delete_transport"
    command = "%s" % (transport_dev)
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Link an iccom to a full duplex test transport device
# and propagate the error expectations
#
# @transport_dev {string} full duplex test device name
# @iccom_dev {string} iccom device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def attach_transport_device_to_iccom_device(transport_dev, iccom_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport" % (iccom_dev)
    command = transport_dev
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Create an iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "c%d" % (channel)
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Delete an iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "d%d" % (channel)
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Set the iccom sysfs channel to read or write and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def set_iccom_sysfs_channel(iccom_dev, channel, err_expectation):
    file = "/sys/devices/platform/%s/channels_ctl" % (iccom_dev)
    command = "s%d" % (channel)
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Writes message to the given iccom sysfs channel
#
# @iccom_dev {string} id of the iccom device
# @channel {number} the destination channel id
# @message {string} message to send
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def iccom_send(iccom_dev, channel, message, err_expectation):
    # Set sysfs channel to work with
    set_iccom_sysfs_channel(iccom_dev, channel, None)
    # Write to the working sysfs channel
    file = "/sys/devices/platform/%s/channels_RW" % (iccom_dev)
    print("iccom_send: " + str(channel))
    command = message
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Reads message from the given iccom sysfs channel and propagate
# the error expectations
#
# @iccom_dev {string} iccom device name
# @channel {string} sysfs channel number
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# Returns:
# Empty String
# String with data read
def iccom_read(iccom_dev, channel, err_expectation):
    # Set sysfs channel to work with
    set_iccom_sysfs_channel(iccom_dev, channel, None)
    # Read from the working sysfs channel
    file = "/sys/devices/platform/%s/channels_RW" % (iccom_dev)
    print("iccom_read: " + str(channel))
    output = fdvio_common.read_sysfs_file(file, err_expectation)
    return output

#----------------------- TEST HELPERS --------------------------------#

# Performs the full duplex xfer on wire
#
# @transport_dev {string} full duplex test device name
# @send_data the bytearray of the data to send
# @error_R_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# RETURNS: the received data as bytearray
def wire_xfer(transport_dev, send_data, error_R_expectation, error_W_expectation):
    write_to_wire(transport_dev, send_data, error_W_expectation)
    sleep(0.1)
    return read_from_wire(transport_dev, error_R_expectation)

# Does the wire full duplex xfer and checks if the
# received data matches expected
#
# @transport_dev {string} full duplex test device name
# @send_data the bytearray of the data to send
# @expected_rcv_data bytearray we expect to receive
# @error_R_expectation {number} the errno which is expected
#                           to be caught on read. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught on write. Example: None, errno.EIO, ...
# @log_msg the extra message to the log in case of failure
#
# Throws an exception if the received data doesn't match expected
def check_wire_xfer(transport_dev, send_data, expected_rcv_data, error_R_expectation, error_W_expectation, log_msg=""):
    rcv_data = wire_xfer(transport_dev, send_data, error_R_expectation, error_W_expectation)
    if (rcv_data != expected_rcv_data):
        raise RuntimeError("Unexpected data on wire%s!\n"
                           "    %s (expected)\n"
                           "    %s (received)\n"
                           % (" (" + log_msg + ")" if len(log_msg) else ""
                              , expected_rcv_data.hex(), rcv_data.hex()))

# Does the wire full duplex ack xfer and checks if the other side
# acks as well.
#
# @transport_dev {string} full duplex test device name
# @error_R_expectation {number} the errno which is expected
#                           to be caught on read. Example: None, errno.EIO, ...
# @error_W_expectation {number} the errno which is expected
#                           to be caught on write. Example: None, errno.EIO, ...
#  @log_msg the extra message to the log in case of failure
#
# Throws an exception if the other side doesn't ack
def check_wire_xfer_ack(transport_dev, error_R_expectation, error_W_expectation, log_msg=""):
        check_wire_xfer(transport_dev, iccom_ack_package()
                                     , iccom_ack_package()
                        , error_R_expectation, error_W_expectation, log_msg)

# Reads the data from the given channel of given device and checks
# if it matches the expected data.
#
# @iccom_dev {string} iccom device name
# @channel the channel id number
# @expected_ch_data the string which is expected to be received from
#   the channel
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
#
# Throws an exception if the read data doesn't match expected
def check_ch_data(iccom_device, channel, expected_ch_data, expected_error):
    # time is a bad companion, but still we need some time to allow the
    # kernel internals to work all out with 100% guarantee, to allow
    # test stability
    sleep(0.3)
    output = iccom_read(iccom_device, channel, expected_error)

    if(expected_error == None):
        if (output != expected_ch_data):
            raise RuntimeError("Unexpected data mismatch in channel!\n"
                               "    %s (expected)\n"
                               "    %s (received)\n"
                               % (expected_ch_data, output))

# Create the RW sysfs files for a full duplex test device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def create_transport_device_RW_files(transport_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport_ctl" % (transport_dev)
    command = "c"
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Deletes the RW sysfs files for a full duplex test device and propagate
# the error expectations
#
# @transport_dev {string} full duplex test device name
# @err_expectation {number} the errno which is expected
#                           to be caught. Example: None, errno.EIO, ...
def delete_transport_device_RW_files(transport_dev, err_expectation):
    file = "/sys/devices/platform/%s/transport_ctl" % (transport_dev)
    command = "d"
    fdvio_common.write_sysfs_file(file, command, err_expectation)

# Provides package on the basis of the package payload
# NOTE: by package payload is meant
#   * packets
# NOTE: NOT included
#   * package header
#   * padding
#   * CRC32
#
# @package_sequential_number the sequential number of the package
#   (unsigned byte in size)
# @package_payload the bytearray of the package payload part
#   (packets data)
#
# RETURNS: the new bytearray - a complete package ready to sent
def iccom_package(package_sequential_number, package_payload):
    PACKAGE_SIZE_BYTES = 64
    CRC32_SIZE_BYTES = 4

    if (package_sequential_number > 0xff) or (package_sequential_number < 0):
        raise ValueError("The package_sequential_number must fit the unsigned"
                         " byte in size, but now given: %s"
                         % (str(package_sequential_number)))
    if (len(package_payload) > PACKAGE_SIZE_BYTES - CRC32_SIZE_BYTES):
        raise RuntimeError("The package payload is too big: %d."
                           " It can me max %d bytes size."
                           % (len(package_payload), PACKAGE_SIZE_BYTES - CRC32_SIZE_BYTES))

    package_header = bytearray((len(package_payload)).to_bytes(2, "big")
                               + package_sequential_number.to_bytes(1, "little"))

    padding_size = (PACKAGE_SIZE_BYTES - len(package_header)
                    - len(package_payload) - CRC32_SIZE_BYTES)

    padded_package = package_header + package_payload + bytearray(padding_size * b"\xff")

    crc32 = zlib.crc32(padded_package)

    full_package = padded_package + bytearray(crc32.to_bytes(CRC32_SIZE_BYTES, "little"))

    return full_package

# RETURNS: the bytearray of the ACK iccom package
def iccom_ack_package():
    return bytearray(b"\xd0")

# RETURNS: the bytearray of the NACK iccom package
def iccom_nack_package():
    return bytearray(b"\xe1")

# Renders the ICCom packet raw data.
# @channel an integer, the ICCom channel number (15 bits, unsigned)
# @payload a bytearray with payload to carry
# @complete bool - if set to True, then the packet is marked as the
#   final packet in packet sequence (last packet needed to assemble the
#   final message on the recevier side).
#
# RETURNS: the bytearray for the packet for given @channel
#   with given @payload and completeness flag
def iccom_packet(channel, payload, complete):
    return (len(payload).to_bytes(2, "big")
            + ((channel & 0x7F80) >> 7).to_bytes(1, "big")
            + ((channel & 0x007F) | (0x80 if complete else 0x00)).to_bytes(1, "big")
            + payload )

# Checks the single package for proper on-wire layout generation
# to ensure the tests themselves are testing against proper data.
# @package_seq_id the package sequential ID
# @package_payload the bytearray of the package payload
# @hex_on_wire the raw hex-string which represents the ground-truth
#   of the on-wire data
# @log_msg the message to test
def iccom_tests_sanity_check_package(package_seq_id, package_payload
                , hex_on_wire, log_msg=""):
        expected_data = bytearray.fromhex(hex_on_wire)
        actual_data = iccom_package(package_seq_id, package_payload)
        if (expected_data != actual_data):
                raise RuntimeError("wrong on-wire package image%s!\n"
                                   "    %s (expected)\n"
                                   "    %s (received)\n"
                                   % ((" (" + log_msg + ")" if len(log_msg) else ""
                                       , expected_data.hex(), actual_data.hex())))

# Launches the test given by the callable @test_sequence
# @test_sequence can run in two modes
#   * provides the test info dict
#   * run the actual test sequence and throw in case of any errors
def fdvio_test(test_sequence, params):
        try:
            test_info = test_sequence({}, get_test_info=True)
            test_id = test_info["test_id"]
            test_descr = test_info["test_description"]

            print("======== TEST: %s ========" % (test_id,))

            test_sequence(params)

            print("%s: PASS" % (test_id,))
        except Exception as e:
            print("%s: FAILED: %s (test description: %s)" % (test_id, str(e), test_descr))

#--------------------------- TESTS -----------------------------------#

def test_lbrp_insmod_rmmod(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("insmod lbrp, check that lbrp dev "
                                          "created, rmmod, check that lbrp dev "
                                          "removed")
                     , "test_id": "fdvio.lbrp_insmod_rmmod" }

        if lbrp_dev_exists():
            raise Exception("Lbrp device exists before lbrp module insertion.")

        insert_lbrp_module()

        if not lbrp_dev_exists():
            raise Exception("Lbrp device was NOT created after lbrp module"
                            " insertion.")

        remove_lbrp_module()

        if lbrp_dev_exists():
            raise Exception("Lbrp device exists after lbrp module removal.")

def test_fdvio_insmod_rmmod(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("insmod fdvio, "
                                          "rmmod fdvio, ensure nothign crashed")
                     , "test_id": "fdvio.fdvio_insmod_rmmod" }

        insert_fdvio_module()

        remove_fdvio_module()

def test_lbrp_write_to_ept_with_no_receiver(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("insmod lbrp, create fdvio remote service"
                                          ", write to remote endpoint" 
                                          "rmmod lbrp, ensure nothign crashed")
                     , "test_id": "fdvio.lbrp_write_to_ept_with_no_receiver" }

        remote_ept_addr = 5432
        service_name = "fdvio"

        insert_lbrp_module()

        lbrp_ensure_no_remote_ept(service_name, remote_ept_addr)

        lbrp_create_remote_ept(service_name, remote_ept_addr)

        lbrp_ensure_remote_ept(service_name, remote_ept_addr)

        lbrp_send_data(service_name, remote_ept_addr, 1111
                       , "hello to nowhere".encode('utf-8'))

        lbrp_remove_remote_ept(service_name, remote_ept_addr)

        lbrp_ensure_no_remote_ept(service_name, remote_ept_addr)

        remove_lbrp_module()

def test_fdvio_dev_creation_1(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": ("insmod lbrp, create fdvio service"
                                          " and endpoint, insmod fdvio, check"
                                          " that fdvio and fdvio_pd devices are"
                                          " created.")
                     , "test_id": "fdvio.fdvio_dev_creation_1" }

        remote_ept_addr = 5432
        service_name = "fdvio"

        # The device created by the rpmsg, to which the fdvio driver gets
        # attached.
        rpmsg_fdvio_dev_name = (lbrp_dev_name() + "." + service_name + ".-1."
                                + str(remote_ept_addr))
        rpmsg_fdvio_dev_path = "/sys/bus/rpmsg/devices/" + rpmsg_fdvio_dev_name

        fdvio_platform_dev_name = "fdvio_pd.1"
        fdvio_platform_dev_path = ("/sys/devices/platform/"
                                   + fdvio_platform_dev_name)

        # Action!

        insert_lbrp_module()

        if os.path.exists(rpmsg_fdvio_dev_path):
            raise Exception(rpmsg_fdvio_dev_path
                            + " device already exists before we created"
                              " remote ept.") 

        lbrp_create_remote_ept(service_name, remote_ept_addr)

        if not os.path.exists(rpmsg_fdvio_dev_path):
            raise Exception(rpmsg_fdvio_dev_path
                            + " must exist after remote endpoint creation on"
                              " lbrp for the %s service with remote addr %d."
                              % (service_name, remote_ept_addr)) 

        if os.path.exists(fdvio_platform_dev_path):
            raise Exception(fdvio_platform_dev_path
                            + " exists before fdvio insertion.")
        
        insert_fdvio_module()

        if not os.path.exists(fdvio_platform_dev_path):
            raise Exception(fdvio_platform_dev_path
                            + " doesn't exist after fdvio insertion.")

        remove_fdvio_module()

        remove_lbrp_module()

def test_fdvio_dev_bind_to_iccom(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": (
                            "insmod lbrp, insmod fdvio, insmod iccom"
                            " create remote fdvio ept (creates the fdvio device)"
                            ", check that fdvio_pd devices is created,"
                            " bind it to iccom, close everything.")
                     , "test_id": "fdvio.fdvio_dev_bind_to_iccom" }

        remote_ept_addr = 5432
        service_name = "fdvio"

        # The device created by the rpmsg, to which the fdvio driver gets
        # attached.
        rpmsg_fdvio_dev_name = (lbrp_dev_name() + "." + service_name + ".-1."
                                + str(remote_ept_addr))
        rpmsg_fdvio_dev_path = "/sys/bus/rpmsg/devices/" + rpmsg_fdvio_dev_name

        fdvio_platform_dev_name = "fdvio_pd.1"
        fdvio_platform_dev_path = ("/sys/devices/platform/"
                                   + fdvio_platform_dev_name)
        iccom_dev = "iccom.0"

        # Action!

        insert_lbrp_module()
        insert_fdvio_module()
        insert_iccom_module()

        lbrp_create_remote_ept(service_name, remote_ept_addr)

        if not os.path.exists(fdvio_platform_dev_path):
            raise Exception(fdvio_platform_dev_path
                            + " doesn't exist after ept creation.")

        create_iccom_device(None)

        attach_transport_device_to_iccom_device(fdvio_platform_dev_name
                                                , iccom_dev, None)

        delete_iccom_device(iccom_dev, None)

        remove_iccom_module()
        remove_fdvio_module()
        remove_lbrp_module()


def test_iccom_fdvio_lbrp_data_path(params, get_test_info=False):

        if (get_test_info):
            return { "test_description": (
                            "insmod lbrp, insmod fdvio, insmod iccom"
                            " create remote fdvio ept (creates the fdvio device)"
                            ", bind iccom to fdvio platform device,"
                            " , create iccom sysfs channel"
                            " , write to this channel, check data pops in lbrp.")
                     , "test_id": "fdvio.iccom_fdvio_lbrp_data_path" }

        remote_ept_addr = 5432
        service_name = "fdvio"

        # The device created by the rpmsg, to which the fdvio driver gets
        # attached.
        rpmsg_fdvio_dev_name = (lbrp_dev_name() + "." + service_name + ".-1."
                                + str(remote_ept_addr))
        rpmsg_fdvio_dev_path = "/sys/bus/rpmsg/devices/" + rpmsg_fdvio_dev_name

        fdvio_platform_dev_name = "fdvio_pd.1"
        fdvio_platform_dev_path = ("/sys/devices/platform/"
                                   + fdvio_platform_dev_name)
        iccom_dev = "iccom.0"
        iccom_ch = 1

        # Action!

        insert_lbrp_module()
        insert_fdvio_module()
        insert_iccom_module()

        lbrp_create_remote_ept(service_name, remote_ept_addr)

        create_iccom_device(None)
        attach_transport_device_to_iccom_device(fdvio_platform_dev_name
                                                , iccom_dev, None)

        create_iccom_sysfs_channel(iccom_dev, iccom_ch, None)
        set_iccom_sysfs_channel(iccom_dev, iccom_ch, None)

        # DATA EXCHANGE CYCLE

        # this thing we will know only when iccom sends us something
        iccom_addr = None
        rcv_data = None

        # Data frame
        print("== Data frame:")
        lbrp2iccom_data = iccom_package(1, iccom_packet(iccom_ch
                                , "hello to iccom!".encode("utf-8"), True))
        iccom2lbrp_data = iccom_package(1, bytearray())

        iccom_send(iccom_dev, iccom_ch, "hello to lbrp!", None)
        sleep(0.4)
        iccom_addr, rcv_data = lbrp_read_data(service_name, remote_ept_addr)

        print("<- real:      %s" % (rcv_data.hex(),))
        print("<- expected:  %s" % (iccom2lbrp_data.hex(),))
        if (rcv_data != iccom2lbrp_data):
            raise Exception("Received unexpected data from ICCom.")

        lbrp_send_data(service_name, remote_ept_addr, iccom_addr, lbrp2iccom_data)
        sleep(0.4)

        # Ack frame
        print("== Ack frame:")
        lbrp2iccom_data = iccom_ack_package()
        iccom2lbrp_data = iccom_ack_package()

        iccom_addr, rcv_data = lbrp_read_data(service_name, remote_ept_addr)

        print("<- real:      %s" % (rcv_data.hex(),))
        print("<- expected:  %s" % (iccom2lbrp_data.hex(),))
        if (rcv_data != iccom2lbrp_data):
            raise Exception("\nData from iccom: %s\n"
                            "Expected data:   %s", (rcv_data.hex() ,iccom2lbrp_data.hex()));

        lbrp_send_data(service_name, remote_ept_addr, iccom_addr, lbrp2iccom_data)
        sleep(0.4)

        # Check if data popped on iccom side
        str2iccom_expected = "hello to iccom!"
        str2iccom_real = iccom_read(iccom_dev, iccom_ch, None)

        print("On ICCom side: <- real:      %s" % (str2iccom_real,))
        print("On ICCom side: <- expected:  %s" % (str2iccom_expected,))

        if str2iccom_real != str2iccom_expected:
            raise Exception("Iccom received distorted data: %s" % (str2iccom_real,))

        delete_iccom_device(iccom_dev, None)

        remove_iccom_module()
        remove_fdvio_module()
        remove_lbrp_module()

#--------------------------- MAIN ------------------------------------#

def run_tests():

        fdvio_test(test_lbrp_insmod_rmmod, {})
        fdvio_test(test_fdvio_insmod_rmmod, {})
        fdvio_test(test_lbrp_write_to_ept_with_no_receiver, {})
        fdvio_test(test_fdvio_dev_creation_1, {})
        fdvio_test(test_fdvio_dev_bind_to_iccom, {})
        fdvio_test(test_iccom_fdvio_lbrp_data_path, {})

if __name__ == '__main__':

    run_tests();
