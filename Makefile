obj-m += net_traffic_monitor.o

net_traffic_monitor-objs := src/main.o \
                            src/packet_processor.o \
                            src/detection_engine.o \
                            src/stats.o \
                            src/procfs.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y := -I$(PWD)/include -Wno-unused-function

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

.PHONY: all clean install help