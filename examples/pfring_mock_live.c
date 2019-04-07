
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "tlsparse.h"

int main(void) {
  char *name = "./data/tls-capture-ecdhe-rsa-pkcs1-sha256.pcap.pcapng";
  FILE *fl = fopen(name, "r");  
  fseek(fl, 0, SEEK_END);  
  uint32_t len = ftell(fl);  
  uint8_t *ret = malloc(len);  
  fseek(fl, 0, SEEK_SET);  
  fread(ret, 1, len, fl);  

  printf("%d\n", len);

  fclose(fl);

  tlsparse_handle_packets(ret, len);
}
