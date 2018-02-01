# ecdaa-erlang
Erlang NIF wrappers for the ECDAA project




```
make compile

make test
```

NOTE: For testing purposes, test [join](https://github.com/xaptum/ecdaa#join-process) process was run

Resulting test files are in `priv/test_data` dir, so we can test the NIFied [signing](https://github.com/xaptum/ecdaa#signing-and-verifying) process 

Credential `cred.bin` and secret key `sk.bin` files are needed for signing the message (test message in `message.bin`) with or without the basename (test basename in `basename.bin`). 

Group public key `gpk.bin` and empty secret key and basename revocation list files `sk_revocation_list.bin` and `bn_revocation_list.bin` are needed for [verifying](https://github.com/xaptum/ecdaa#signing-and-verifying) the generated signature.