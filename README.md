# What is this

This is the Full Duplex VirtIO (ICCom compatible) driver.

It is located between ICCom on top and the transport layers
at the bottom.

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

So, the Fdvio driver provides the Full Duplex Symmetrical Transport Interface
to the ICCom, and uses the Rpmsg IF to implement the functionality.
