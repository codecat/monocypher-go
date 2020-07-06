# monocypher-go
Go bindings for [Monocypher](https://monocypher.org/).

Loosely based on [demonshredder's bindings](https://github.com/demonshreder/monocypher-go), but has a few differences:

* Only contains `crypto_sign` and `crypto_check` (because that's what I needed)
* Updated to the latest version of Monocypher
* Fixed some building issues and memory leaks
