FW_ROOT ?= $(PWD)/../3rdparty
FW_ROOT_BUILD ?= $(FW_ROOT)/build

LIB_BUILD=$(FW_ROOT_BUILD)

# Default target, can be overriden by command line or environment
RTE_TARGET ?= $(shell uname -m)-native-linuxapp-gcc
RTE_SDK ?= $(FW_ROOT)/dpdk

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = wy_nat

# all source are stored in SRCS-y
SRCS-y := main.c
SRCS-y += base.c
SRCS-y += m_signal.c
SRCS-y += m_conf.c
SRCS-y += m_plat.c
SRCS-y += m_log.c
SRCS-y += m_zk.c
SRCS-y += m_core.c
SRCS-y += m_pcap.c
SRCS-y += m_kafka.c
SRCS-y += m_kni.c
SRCS-y += m_nl.c
SRCS-y += cjson.c
SRCS-y += bitmap.c

CFLAGS += -I$(SRCDIR) -I$(SRCDIR)/include -I$(FW_ROOT_BUILD)/include -I$(FW_ROOT_BUILD)/include/zookeeper -I$(FW_ROOT_BUILD)/include/librdkafka 
#-I/usr/src/kernels/3.10.0-514.2.2.el7.x86_64/include
CFLAGS += -O3 $(USER_FLAGS) -g -lpthread -lz -lcurl  -lcrypto   -lssl -lsasl2   -lrt -Wuninitialized
LDFLAGS += $(FW_ROOT_BUILD)/lib/libev.a $(FW_ROOT_BUILD)/lib/libzookeeper_mt.a $(FW_ROOT_BUILD)/lib/librdkafka++.a $(FW_ROOT_BUILD)/lib/librdkafka.a
#CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk
