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

# Workqueue - use the system WQ
RUN make -C ${kernel_source_dir_x86} M=${repo_path} \
        CONFIG_BOSCH_DRIVERS=y \
        CONFIG_BOSCH_FDVIO_DRIVER=m \
        CONFIG_CHECK_SIGNATURE=n \
        && rm -rf ${repo_path}/*
COPY . .

