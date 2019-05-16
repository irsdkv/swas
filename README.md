# Snark Wallet Atomic Swaps library

This library is designed to help to perform atomic crosschain swaps using the XCAT algorithm ([https://z.cash/blog](https://z.cash/blog/tag/xcat/)).

Bitcoin SegWit transactions supported.

Zcash v4 (Overwintered) transactions supported.

Tested on Zcash node v2.0.1 and Bitcoin Core node v0.17.0 (*TESTNET ONLY*).

## Example

See demo-app in [src/bin/swas-demo.rs](https://github.com/rndintec/swas/blob/master/src/bin/swas-demo.rs)

Demonstration of usage available on [YouTube](url)

## Build
```
cargo build
```
or
```
cargo build --release
```

## Docs
```
cargo doc --open
```

## Run demo CLI app
Set up *~/.swas/swas.conf* file, run Bitcoin and Zcash nodes and
```
cargo run
```

## Example of ~/.swas/swas.conf

```
btcrpcport=18332
btcrpcuser="username"
btcrpcpassword="password"

zecrpcport=18232
zecrpcuser="username"
zecrpcpassword="password"

minconfirmaions=1
```
# License
The MIT License (MIT)

Copyright (c) 2019 INTEC LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
