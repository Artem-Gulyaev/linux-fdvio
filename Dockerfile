# NOTE: Default build for the fdvio modules
#       with its different variants
FROM iccom:latest AS fdvio

# Base (default) version
ARG kernel_source_dir_x86=/repos/linux_x86/
ARG kernel_source_dir_arm=/repos/linux_arm/

##  Prepare the fdvio sources

ENV repo_path=/repos/linux-fdvio
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# TODO: MOVE THIS TO KERNEL MODULES BASE IMAGE

RUN apt-get update && apt-get install --yes --fix-missing gdb libncurses-dev

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

##  Fdvio Variants Builds

# x86
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        KDIR=${kernel_source_dir_x86} \
        CONFIG_BOSCH_DRIVERS=y \
        CONFIG_BOSCH_FDVIO_DRIVER=m \
        CONFIG_CHECK_SIGNATURE=n \
		CONFIG_BOSCH_FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC=5000 \
		CONFIG_BOSCH_FDVIO_ERROR_SILENCE_TIME_MSEC=30

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
        CONFIG_CHECK_SIGNATURE=n \
		CONFIG_BOSCH_FDVIO_THEIR_DATA_WAIT_TIMEOUT_MSEC=5000 \
		CONFIG_BOSCH_FDVIO_ERROR_SILENCE_TIME_MSEC=30

RUN mkdir -p ${INITRAMFS_CHROOT_ARM}/modules              \
    && cp ${repo_path}/src/fdvio.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/    \
    && cp ${repo_path}/src/loopback_rpmsg_proc.ko         \
        ${INITRAMFS_CHROOT_ARM}/modules/


###################### TEST PREPARATION BLOCK #######################

FROM fdvio AS fdvio-test

## SIMPLE INSERTION / REMOVAL TEST
RUN python-to-initramfs-x86 ${repo_path}/tests/fdvio_tests.py

COPY tests/insmod_rmmod_test.sh /builds/shell-tests/
RUN shell-to-initramfs-arm /builds/shell-tests/insmod_rmmod_test.sh

COPY tests/arm_basic_test.sh /builds/shell-tests/
RUN shell-to-initramfs-arm /repos/linux-fdvio/tests/arm_basic_test.sh

######################### TEST RUN BLOCK ############################

# x86

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
		&& grep "fdvio.iccom_fdvio_lbrp_data_multipackage_msgs_stress: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_multipackage_msgs_stress: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.iccom_fdvio_lbrp_data_multipackage_msgs_stress_racing: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_multipackage_msgs_stress_racing: \033[0;32mPASS\033[0m" \
		&& grep "fdvio.iccom_fdvio_lbrp_data_error_size_mismatch: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_error_size_mismatch: \033[0;32mPASS\033[0m" \
    	&& grep "fdvio.iccom_fdvio_lbrp_data_error_timeout: PASS" /qemu_run_x86.log > /dev/null \
			&& echo "fdvio.iccom_fdvio_lbrp_data_error_timeout: \033[0;32mPASS\033[0m" \


## ARM

# TODO: here must be the testing up to userspace level

#RUN cd /repos \
#        && git clone ssh://git@sourcecode.socialcoding.bosch.com:7999/cm_ci2_linux/libiccom.git
#RUN mkdir -p /builds/libiccom && cd /builds/libiccom \
#    && cmake -DCMAKE_CXX_COMPILER=arm-linux-gnueabi-g++ /repos/libiccom \
#    && make && cmake --install . --prefix /builds/initramfs_arm/content

##################### MANUAL STACK IN ARM ###################

# Create the dtb file
RUN mkdir -p /builds/linux_arm/device_tree
COPY ./device_tree/ast2500.dts /builds/linux_arm/device_tree/
RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/ast2500.dts \
        > /builds/linux_arm/device_tree/ast2500.dtb

RUN rm /builds/initramfs_arm/content/tests/*
RUN shell-to-initramfs-arm /repos/linux-fdvio/tests/arm_basic_test.sh

RUN run-qemu-tests-arm /builds/linux_arm/device_tree/ast2500.dtb

# Check the expected results
RUN grep "fdvio.arm.lbrp.lbrp_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.lbrp.lbrp_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.lbrp.fdvio_platform_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.lbrp.fdvio_platform_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.iccom_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.iccom_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.iccom_skif_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.iccom_skif_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.udev_stack.min_com: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.udev_stack.min_com: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.reached_shutdown: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.reached_shutdown: \033[0;32mPASS\033[0m"

######################### DT STACK IN ARM ###################

# Create the dtb file
RUN mkdir -p /builds/linux_arm/device_tree
COPY ./device_tree/ast2500-auto.dts /builds/linux_arm/device_tree/
RUN dtc -I dts -O dtb /builds/linux_arm/device_tree/ast2500-auto.dts \
        > /builds/linux_arm/device_tree/ast2500-auto.dtb

RUN rm /builds/initramfs_arm/content/tests/*
RUN shell-to-initramfs-arm /repos/linux-fdvio/tests/arm_dt_test.sh

RUN run-qemu-tests-arm /builds/linux_arm/device_tree/ast2500-auto.dtb

RUN grep "fdvio.arm.dt.lbrp.lbrp_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.lbrp.lbrp_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.dt.lbrp.fdvio_platform_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.lbrp.fdvio_platform_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.dt.iccom_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.iccom_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.dt.iccom_skif_dev_created: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.iccom_skif_dev_created: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.dt.udev_stack.min_com: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.udev_stack.min_com: \033[0;32mPASS\033[0m" \
        && grep "fdvio.arm.dt.reached_shutdown: PASS" /qemu_run_arm.log > /dev/null \
			&& echo "fdvio.arm.dt.reached_shutdown: \033[0;32mPASS\033[0m" \

