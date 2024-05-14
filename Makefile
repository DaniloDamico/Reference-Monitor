IMAGE_PATH := $(shell sed -n -e "s/^\#define IMAGE_NAME *\(.*\)/\1/p" $(PWD)/logfilefs/logfilefs.h)
MOUNT_PATH := $(shell sed -n -e "s/^\#define MOUNT_PATH *\(.*\)/\1/p" $(PWD)/logfilefs/logfilefs.h)

obj-m += reference_monitor.o
reference_monitor-objs += main.o logfilefs/dir.o logfilefs/file.o logfilefs/logfilefs.o

all:
	dd bs=4096 count=10000 if=/dev/zero of=$(IMAGE_PATH)
	mkdir -p $(MOUNT_PATH)
	
	gcc ./logfilefs/mklogfs.c -o ./logfilefs/mklogfs
	./logfilefs/mklogfs $(IMAGE_PATH)
	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	rm -rf $(MOUNT_PATH)
	rm -f $(IMAGE_PATH)
	rm -f ./logfilefs/mklogfs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
install:
	sudo insmod reference_monitor.ko logfs_directory=$(PWD)
	sudo mount -o loop -t logfilefs $(IMAGE_PATH) $(MOUNT_PATH)

uninstall:
	sudo umount $(MOUNT_PATH)
	sudo rmmod reference_monitor.ko

