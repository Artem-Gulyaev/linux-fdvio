# Bosch Fdvio Driver Makefile

# We fix the kernel version to make the build reproducible
# NOTE: if you change it here and then use in docker, you will
# 		need to rebuild the docker images we inherit from
KVER ?= 5.4.0-97-generic
KDIR ?= /lib/modules/${KVER}/build

.PHONY: test install uninstall docker-image

# Build on current machine with given (current kernel by default) kernel
default:
	$(MAKE) -C $(KDIR) M=$$PWD \
		CONFIG_BOSCH_FDVIO=m

# Install to current machine
install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

# Try to remove the installed driver from current machine
uninstall:
	rm -f /lib/modules/${KVER}/extra/src/fdvio.ko

# Build Docker deployed image (Docker image with built and installed Fdvio driver)
docker-image:
	cd $$PWD && scripts/docker_build_wrapper.sh 	\
		 			-t linux-fdvio 					\
		            -f ./Dockerfile.docker-image . 	\
		&& echo "docker-image: \033[0;32mOK\033[0m"

# Test ourselves in Docker environment (similar to docker-image, but
# usually builds various build configurations and if all fine, just removes
# the build artifacts)
test:
	cd $$PWD && scripts/docker_build_wrapper.sh   . \
		&& echo "test: \033[0;32mOK\033[0m"

# combines both: `test` and `docker-image` target
base: docker-image test
	echo "base: \033[0;32mOK\033[0m"
