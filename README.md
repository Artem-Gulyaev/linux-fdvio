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
