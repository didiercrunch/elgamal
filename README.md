elgamal
=======

Pure elgamal cryptosystem implemented in Go

[![travis](https://travis-ci.org/didiercrunch/elgamal.svg)](https://travis-ci.org/didiercrunch/elgamal/)


#### introduction

Implementation of the El Gamal cryptosystem.  See
http://en.wikipedia.org/wiki/ElGamal_encryption for an introduction.

The difference between this implementation and the one at golang.org/x/crypto/openpgp/elgamal
is the use of absolutly no padding here.

The absance of padding is cool if you want to encrypt numbers and need to make algebra
on the cypher texts.  The use of padding is needed when you encrypt data and you
do not want to allow algebraic operations on the cypher texts.

Another important feature of the library is the ease of serilisation of all
the structs in JSON and BSON.


#### caveat

As any cryptographic library, if you use it, you need to *trust* it.  Unfortunatly,
this library as not been verified by a third party.  There might be some bugs and
vulnerabilities.  If you find one, please fill a bug.


#### documentation

Thanks to godoc.org, the documentation is available at
http://godoc.org/github.com/didiercrunch/elgamal
