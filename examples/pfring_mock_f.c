
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "tlsparse.h"

int main(void) {
  char *name = "./data/tls-capture-ecdhe-rsa-pkcs1-sha256.pcap.pcapng";
  tlsparse_handle_pcap(name);
}
