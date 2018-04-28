lber
====

lber is a minimalist pure-lua X.690 BER/DER/CER decoder released under the ISC license.
It is currently in a state appropriately described as "very alpha".

Tests
-----

Currently the only part covered by unit tests is the bit operations component.
Note that it uses lua 5.3 bitwise operations or the (luajit) bitop library where available.
