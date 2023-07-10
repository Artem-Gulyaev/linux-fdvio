# What is this

This is the Full Duplex VirtIO (ICCom compatible) driver.

It is located between ICCom on top and the transport layers
at the bottom.

```
|---------------------|
|        ICCom        |
|---------------------|
|---------------------| <--- Full Duplex Symmetrical Transport IF
|       *Fdvio*       |
|---------------------|
|---------------------| <--- The Rpmsg IF
|        Rpmsg        |
|---------------------|
|---------------------|
|        VirtIO       |
|---------------------|
           ^
           |
           v
      shared memory         
```

So, the Fdvio driver provides the Full Duplex Symmetrical Transport Interface
to the ICCom, and uses the Rpmsg IF to implement the transport functionality.

Fdvio allows the ICCom stack to be used on top of the shared memory
transports, while retaining the ICCom capabilty to work on top of, say,
SPI bus using the SymSPI drivers.

## Debugging hints

### To copy files from docker to host

To copy the file from docker using cat command:

```
# Copy Linux x86 config to host
docker run --rm --entrypoint cat fdvio /repos/linux_x86/.config > ./vm/linux-config/x86.config
```

```
# Copy Linux ARM config to host
docker run --rm --entrypoint cat fdvio /repos/linux_arm/.config > ./vm/linux-config/arm.config
```

NOTE: Linux kernels are configued to be with debug symbols.

NOTE: GDB is available in docker

### To debug kernel within the docker

* start the docker

  ```
  docker run -it fdvio
  ```
* inside the image
  
  ```
  cd /repos/linux_x86 && gdb vmlinux
  ```

### To update Docker image after doing the changes in interactive mode

* do your changes using something like:
  ```
  docker run -it fdvio` or similar
  ```
* find the corresponding container id (list last container id):
  ```
  docker ps -l
  ```
* commit your changes from container to the image:
  ```
  docker commit <container_id> fdvio
  ```

