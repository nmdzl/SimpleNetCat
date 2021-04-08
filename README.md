# SimpleNetCat

This is the first individual project of NCSU ECE 574 (Computer & Network Security) in 2020 Spring semester.

The project is to provide *confidentiality* and *integrity* in a simple version of [NetCat](https://www.freebsd.org/cgi/man.cgi?nc) - a Simple Encrypted File Transfer Program.

The program contains following features:

- Use AES-265 as encryption function, HMAC as MAC function. Use AES-GCM security mode to apply encrypt-then-MAC (EtM).
- Implement functionalities of both server and clients by command options.
- Support simultaneous upload and download at both server and client sides.

## Encryption and Decryption

For encryption, a 16-byte-long *key* is accepted, and a 16-byte-long *salt* (or *nonce*) and a 12-byte-long *initialization vector* (iv) are created. A 16-byte-long *tag* is produced for MAC check. The same four values are also needed or generated for decryption.

In this program, the messages being transferred follow a pattern as "salt, iv, ciphertext, tag". 

## Requirements

The program was developed with Python 3.6.2.
