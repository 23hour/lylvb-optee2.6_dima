# obj-m += dima_init.o

# all:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# clean:
# 	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
# #
# # Makefile for building the Dynamic Integrity Measurement Architecture(DIMA)
# #
# obj-$(CONFIG_DIMA) += dima.o

# dima-y := dima_init.o dima_cmd.o dima_fs.o

obj-m += message.o
message-m := init.o get_process_message.o dima_netlink.o

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean	
