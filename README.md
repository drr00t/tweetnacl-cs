#TweetNaCl-cs

|Branch|Build|Code Cover|
|:------|--------:|--------:|
|master|.Net [![Build status](https://ci.appveyor.com/api/projects/status/a3463mlqmh310och/branch/master?svg=true)](https://ci.appveyor.com/project/drr00t/tweetnacl-cs/branch/master)<br>Mono [![Build Status](https://travis-ci.org/drr00t/tweetnacl-cs.svg)](https://travis-ci.org/drr00t/tweetnacl-cs)| Coveralls [![Coverage Status](https://coveralls.io/repos/github/drr00t/tweetnacl-cs/badge.svg?branch=master)](https://coveralls.io/github/drr00t/tweetnacl-cs?branch=master)|

## About Project
A C# port of original [TweetNaCl](http://tweetnacl.cr.yp.to/index.html) C language implementation version 20140427.

**:warning: The library is not stable yet and API will change and was not independently reviewed.** If you can help reviewing it, please [contact me](mailto:adribeiro (at) gmail.com).


##Documentation
* [Overview](#overview)
* [Installation](#installation) (todo)
* [Usage](#usage)
  * [Public-key authenticated encryption (Box)](#public-key-authenticated-encryption-box)
  * [Secret-key authenticated encryption (SecretBox)](#secret-key-authenticated-encryption-secretbox)
  * [Scalar Multiplication](#scalar-multiplication)
  * [Signatures](#signatures)
  * [Hashing](#hashing)
  * [Random bytes generation](#random-bytes-generation)
  * [Constant-time comparison](#constant-time-comparison)
* [Contributors](#contributors)
* [Who is using](#who-using)


### Public-key authenticated encryption (box)

Implements *curve25519-xsalsa20-poly1305*.

#### Byte[] CryptoBoxKeypair(Byte[] secretKey)

The CryptoBoxKeypair function randomly generates a <b>secretKey</b> and a corresponding public key. The secretKey array must have size equal to <b>crypto_box_SECRETKEYBYTES</b>

#### Byte[] CryptoBox(Byte[] message, Byte[] nonce, Byte[] publicKey, Byte[] secretKey)

The function encrypts and authenticates a <b>message</b> using the <b>nonce</b>, receiver´s <b>publicKey</b> and sender´s <b>secretKey</b>.

#### Byte[] CryptoBoxOpen(Byte[] cipheredMessage, Byte[] nonce, Byte[] publicKey, Byte[] secretKey)

The function verifies and decrypts a cipherMessage using the receiver's secretKey, the sender's publicKey, and a nonce.

#### Byte[] CryptoBoxBeforenm(Byte[] publicKey, Byte[] secretKey)

Applications that send several messages to the same receiver can gain speed by splitting CryptoBox into two steps, <b>CryptoBoxBeforenm</b> and <b>CryptoBoxAfternm</b>.

#### Byte[] CryptoBoxAfternm(Byte[] message, Byte[] nonce, Byte[] k)
#### Byte[] CryptoBoxOpenAfternm(Byte[] cipheredMessage, Byte[] nonce, Byte[] k)
#### Byte[] CryptoSignKeypair(Byte[] secretKey)
#### Byte[] CryptoSign(Byte[] message, Byte[] secretKey)
#### Byte[] CryptoSignOpen(Byte[] signedMessage, Byte[] publicKey)
#### Byte[] CryptoScalarmult(Byte[] n, Byte[] p)

Scalar multiplication is a curve25519 implementation.

#### Byte[] CryptoScalarmultBase(Byte[] n)

The CryptoScalarmultBase function computes the scalar product of a standard group element and an integer n

####
####
####
####
####

##Third-party libraries


##Who is using

##License
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
