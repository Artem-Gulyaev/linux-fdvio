# syntax=docker/dockerfile:1.3-labs

# NOTE: Default build for the fdvio modules
#       with its different variants
FROM iccom:latest AS fdvio

# Base (default) version
ARG kernel_source_dir_x86=/repos/linux_x86/
ARG kernel_source_dir_arm=/repos/linux_arm/

##  Prepare the compatible Linux kernels first

# x86
RUN cd /repos/linux_x86
COPY ./vm/linux-config/x86.config  /repos/linux_x86/.config
RUN make_apply_linux_x86

# ARM
RUN cd /repos/linux_arm
COPY ./vm/linux-config/arm.config  /repos/linux_arm/.config
RUN make_apply_linux_arm

##  Prepare the fdvio sources

ENV repo_path=/repos/linux-fdvio
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# TODO: MOVE THIS TO KERNEL MODULES BASE IMAGE

RUN apt-get install --yes gdb libncurses-dev

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

##  Fdvio Variants Builds

# x86
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        KDIR=${kernel_source_dir_x86} \
        CONFIG_BOSCH_DRIVERS=y \
        CONFIG_BOSCH_FDVIO_DRIVER=m \
        CONFIG_CHECK_SIGNATURE=n

RUN mkdir -p ${INITRAMFS_CHROOT_X86}/modules              \
    && cp ${repo_path}/src/fdvio.ko         \
        ${INITRAMFS_CHROOT_X86}/modules/    \
    && cp ${repo_path}/src/loopback_rpmsg_proc.ko         \
        ${INITRAMFS_CHROOT_X86}/modules/

# ARM
RUN make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- \
            -C ${kernel_source_dir_arm} \
            M=${repo_path} \
            KDIR=${kernel_source_dir_arm} \
            CONFIG_BOSCH_DRIVERS=y \
            CONFIG_BOSCH_FDVIO_DRIVER=m \
            CONFIG_CHECK_SIGNATURE=n

RUN mkdir -p ${INITRAMFS_CHROOT_ARM}/modules              \
    && cp ${repo_path}/src/fdvio.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/    \
    && cp ${repo_path}/src/loopback_rpmsg_proc.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/


###################### TEST PREPARATION BLOCK #######################

FROM fdvio AS fdvio-test

## SIMPLE INSERTION / REMOVAL TEST
RUN python-to-initramfs-x86 ${repo_path}/tests/fdvio_tests.py

######################### TEST RUN BLOCK ############################

## x86

RUN run-qemu-tests-x86

# Check the expected results
RUN echo "************** OVERALL RESULT ******************" \
	 	&& grep "fdvio.lbrp_insmod_rmmod: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.lbrp_insmod_rmmod: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.fdvio_insmod_rmmod: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.fdvio_insmod_rmmod: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.lbrp_write_to_ept_with_no_receiver: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.lbrp_write_to_ept_with_no_receiver: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.fdvio_dev_creation_1: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.fdvio_dev_creation_1: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.fdvio_dev_bind_to_iccom: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.fdvio_dev_bind_to_iccom: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.iccom_fdvio_lbrp_data_path: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_path: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.iccom_fdvio_lbrp_data_stress: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_stress: \033[0;32mPASS\033[0m" \
        
## ARM

## Create the dtb file
#RUN mkdir -p /builds/linux_arm/device_tree
#COPY ./device_tree/versatile-pb_fdvio.dts /builds/linux_arm/device_tree
#RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/versatile-pb_fdvio.dts \
#        > /builds/linux_arm/device_tree/versatile-pb_fdvio.dtb
#
#RUN run-qemu-tests-arm /builds/linux_arm/device_tree/versatile-pb_fdvio.dtb
#
## Check the expected results
#RUN grep "${TEST_NAME}.kernel: PASS" /qemu_run_arm.log
