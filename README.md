# ECDSA Attack 
### Rust PFRing integration

TODO: 
design the system for managing connection flow ssl data split across numerous packets.
(i.e. client / server public keys, signature, and cert which can be split in many ways).

Consider using:
- struct that is filled during batch handle and cleared / trash collected at end of batch
- thread with shared memory or IPC.


Useful RFC's
* [X.509 RFC 5280](https://tools.ietf.org/html/rfc5280)
* [TLS 1.2 RFC 5246](https://tools.ietf.org/html/rfc5246)
* [TLS 1.3 RFC 8446](https://tools.ietf.org/html/rfc8446)
* [TCP RFC 793](https://tools.ietf.org/html/rfc793)
* [ECDSA RFC 6979](https://tools.ietf.org/html/rfc6979)
* [ECC for TLS RFC 4492](https://tools.ietf.org/html/rfc4492)




