IMAGE_PATH := $(shell pwd)/image
MOUNT_PATH := /mnt/mountfs/

obj-m += reference_monitor.o
reference_monitor-objs += main.o logfilefs/dir.o logfilefs/file.o logfilefs/logfilefs.o cryptography.o module.o

all:
	dd bs=4096 count=10000 if=/dev/zero of=$(IMAGE_PATH)
	sudo mkdir -p $(MOUNT_PATH)
	
	gcc ./logfilefs/mklogfs.c -o ./logfilefs/mklogfs
	./logfilefs/mklogfs $(IMAGE_PATH)
	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	sudo rm -rf $(MOUNT_PATH)
	rm -f $(IMAGE_PATH)
	rm -f ./logfilefs/mklogfs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
install:
	sudo insmod reference_monitor.ko
	sudo mount -o loop -t logfilefs $(IMAGE_PATH) $(MOUNT_PATH)

uninstall:
	sudo umount $(MOUNT_PATH)
	sudo rmmod reference_monitor.ko

