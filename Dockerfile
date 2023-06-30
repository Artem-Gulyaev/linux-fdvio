# syntax=docker/dockerfile:1.3-labs

# NOTE: Default build for the fdvio modules
#       with its different variants
FROM bosch-linux-full-duplex-interface:latest AS fdvio

# Base (default) version
ARG kernel_source_dir_x86=/repos/linux_x86/
ARG kernel_source_dir_arm=/repos/linux_arm/

ENV repo_path=/repos/linux-fdvio
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

##  Fdvio Variants Builds

# x86
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_DRIVERS=y \
        CONFIG_BOSCH_FDVIO_DRIVER=m \
        CONFIG_CHECK_SIGNATURE=n

RUN mkdir -p ${INITRAMFS_CHROOT_X86}/modules              \
    && cp ${repo_path}/src/fdvio.ko         \
        ${INITRAMFS_CHROOT_X86}/modules/

# ARM
RUN make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -C ${kernel_source_dir_arm} M=${repo_path} \
        CONFIG_BOSCH_DRIVERS=y \
        CONFIG_BOSCH_FDVIO_DRIVER=m \
        CONFIG_CHECK_SIGNATURE=n

RUN mkdir -p ${INITRAMFS_CHROOT_ARM}/modules              \
    && cp ${repo_path}/src/fdvio.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/


###################### TEST PREPARATION BLOCK #######################

FROM fdvio AS fdvio-test

ARG TEST_NAME="bosch-linux-ext-modules-build-test"

## SIMPLE INSERTION / REMOVAL TEST
RUN shell-to-initramfs-x86 ${repo_path}/tests/insmod_rmmod_test.sh
RUN shell-to-initramfs-arm ${repo_path}/tests/insmod_rmmod_test.sh

######################### TEST RUN BLOCK ############################

## x86

RUN run-qemu-tests-x86

# Check the expected results
RUN grep "${TEST_NAME}.kernel: PASS" /qemu_run_x86.log

## ARM

# Create the dtb file
RUN mkdir -p /builds/linux_arm/device_tree
COPY ./device_tree/versatile-pb_fdvio.dts /builds/linux_arm/device_tree
RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/versatile-pb_fdvio.dts \
        > /builds/linux_arm/device_tree/versatile-pb_fdvio.dtb

RUN run-qemu-tests-arm /builds/linux_arm/device_tree/versatile-pb_fdvio.dtb

# Check the expected results
RUN grep "${TEST_NAME}.kernel: PASS" /qemu_run_arm.log
