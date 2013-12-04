mod_auth_memcookie
==================

An Apache module for cookie-based authentication


dependencies
==================

This is designed for Apache 2.x, but I've only tested it with Apache 2.2 under EL6.  Your mileage may vary there.  It also targets libmemcached 1.0, whereas the default on EL6 (and probably EL4/EL5) is libmemcached 0.31.  You can easily install libmemcached 1.0.17 (the version I used during development) from https://github.com/tobz/libmemcached-packages - the source and spec files are there if you feel more comfortable building your own RPMs, but the packages are ready to go, built cleanly on an EL6 host without extraneous dependencies.
