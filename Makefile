# Makefile, modified from PF_RING examples Makefile.in

#
# PF_RING
#
PFRINGDIR  = ./PF_RING/userland/lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# PF_RING aware libpcap
#
PCAPDIR    = ./PF_RING/userland/libpcap
LIBPCAP    = ${PCAPDIR}/libpcap.a

PFUTILSDIR = ./PF_RING/userland/examples

#
# Search directories
#
PFRING_KERNEL= ./PF_RING/kernel/
INCLUDE    = -I${PFRING_KERNEL} -I${PFRING_KERNEL}/plugins -I${PFRINGDIR} -I${PFUTILSDIR} -I${PCAPDIR} -Ithird-party -I`${PFRINGDIR}/pfring_config --include`

#
# C compiler and flags
#
CC         = gcc
CFLAGS     =  -O2 -DHAVE_PF_RING -Wall ${INCLUDE} -DENABLE_BPF -D HAVE_PF_RING_ZC
#CFLAGS     += -g

#
# User and System libraries
#
DEBUG_OR_RELEASE = release
LIBS       =  ${LIBPFRING} ${LIBPCAP} `${PFRINGDIR}/pfring_config --libs` -lrt -Lrust-src/target/${DEBUG_OR_RELEASE} -lrsa_faulty_signatures -ldl -lm -L/usr/local/lib -lssl -lcrypto -lpthread

all: rsa-faulty-signatures

rsa-faulty-signatures.o: main.c #${PFUTILSDIR}/pfutils.c
	${CC} ${CFLAGS} -c $< -o $@

rust-code:
	cd ./rust-src/;	cargo build --${DEBUG_OR_RELEASE}

rsa-faulty-signatures: rsa-faulty-signatures.o ${LIBPFRING} rust-code
		${CC} ${CFLAGS} $< -o $@ ${LIBS}

clean:
	@rm -f rsa-faulty-signatures *.o *~
	@rm -rf ./rust-src/target
