# BEAST-PoC (chosen-plaintext attack)

This proof of concept is focused on the cryptography behind the BEAST (Browser Exploit Against SSL/TLS) attack presented by Thai Duong and Juliano Rizzo on September 23, 2011. This a [chosen-plaintext attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack) and this allow you to retrieve sensitives informations if the Transport Layer Security used is TLS1.0 or SSLv3.
The orginal proof of concept can be found here : [Here come the Ninjas](http://netifera.com/research/beast/beast_DRAFT_0621.pdf)

**Note**: This is also an implementation of the vulnerability originally discovered by [Phillip Rogaway](https://en.wikipedia.org/wiki/Phillip_Rogaway). Discovered in 2002, there was no exploit released until BEAST in 2011. OpenSSL already knew the [problem](https://www.openssl.org/~bodo/tls-cbc.txt) and this why they updated TLS1.0 to TLS1.1 in April 2006.

> 2 The CBC IV for each record except the first is the previous records' last
   ciphertext block.  Thus the encryption is not secure against adversaries who
   can adaptively choose plaintexts;

### Be the BEAST

#### 1. SSLv3/TLS1.0 and CBC cipher mode

SSLv3/TLS1.0 are protocols to encrypt/decrypt and secure your data. In our case, they both use the [CBC cipher mode chainning](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) . The plaintext is divided into block regarding the encryption alogithm (AES,DES, 3DES) and the length is a mulitple of 8 or 16. If the plaintext don't fill the length, a [padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is added at the end to complete the missing space. I strongly advice you to open this images of [encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png) and [decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png) to read this readme.


Encryption | Decryption
--- | --- 
C<sub>i</sub> = E<sub>k</sub>(P<sub>i</sub> ⊕ C<sub>i-1</sub>), and C<sub>0</sub> = IV | P<sub>i</sub> = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>i-1</sub>, and C<sub>0</sub> = IV
 
Basically this is just some simple XOR, you can also watch this video (not me) https://www.youtube.com/watch?v=0D7OwYp6ZEc. 

I will introduce the [IV](https://en.wikipedia.org/wiki/Initialization_vector) in the next point. Remember that all this property will help us to drive our attack.

#### 2. Cryptology

When we use the CBC we need a vector initialisation call IV. This IV is random (or fixed) but in any case it should not be predictable from anyone. In TLS1.0 and SSLv3 the first IV of the request is random, fine. But to gain some time and not generate a new random IV every time, the implemenation of TLS1.0 and SSLv3 used the last block of the previous cipher text has an IV. In other words, the IV is now guessable.
We will assume the length of each block will be 8 (DES) and the attacker have a MiTM to retrieve all the cipher.

Example :

C<sub>0</sub> | C<sub>...</sub> | C<sub>i-1</sub> | C<sub>i</sub> | C<sub>i+1</sub> |C<sub>n</sub>

Now the interesting part, this is the different cryptographic steps of the attack to retrieve one byte : 

* first we send a request call C² to get the last block of the cipher meaning the next IV of the second request
* this is a chosen plaintext attack, so the attacker can send this message `bbbbbbbTHIS_IS_A_SECRET_COOKIE` through the victim.

You can notice the seven `b` before the secret cookie. If the length of a block is 8 we need to push 7 know bytes. This information is very important, the attacker know the 7 first bytes of the first block. 

But why ? This allow us to have only 256 possibilty to find one byte and not 256^8 to find 8 bytes !  

Now the victim send the request and it will be encrypted like this :

C<sub>0</sub> | C<sub>1</sub> | C<sub>2</sub> | C<sub>3</sub> | C<sub>4</sub>

Where C<sub>0</sub> = E<sub>k</sub>(IV ⊕ bbbbbbbT) = E<sub>k</sub>(C²<sub>n</sub> ⊕ bbbbbbbT)

* the attacker want to retrieve the information in the block C<sub>0</sub> C<sub>1</sub>, C<sub>2</sub> ... **he always need the previous block**
* a third request is send after build a special block P'<sub>0</sub>. The first block will be encrypted like this : C'<sub>0</sub> = E<sub>k</sub>(P'<sub>0</sub> ⊕ IV')
Since this is a chosen plaintext attack, the attacker can construct a block P'<sub>0</sub> like this :

P'<sub>0</sub> = C²<sub>n</sub> ⊕ C<sub>4</sub> ⊕ bbbbbbbX

The only unknow element is `X`, there is 256 possibilities so he will try max 256 char.
The request is send and encrypt like this :

C'<sub>0</sub> = E<sub>k</sub>(P'<sub>0</sub> ⊕ IV') <br>
C'<sub>0</sub> = E<sub>k</sub>(C²<sub>n</sub> ⊕ C<sub>4</sub> ⊕ bbbbbbbX ⊕ IV') or C<sub>4</sub> ⊕ IV' = 0 <br>
C'<sub>0</sub> = E<sub>k</sub>(C²<sub>n</sub> ⊕ bbbbbbbX) <br>
C'<sub>0</sub> = E<sub>k</sub>(IV ⊕ bbbbbbbX) <br>

Now he compares : C'<sub>0</sub> and C<sub>0</sub>, if they are equal, then he just found the byte `X` in position 8. If it doesn't match, he retries with another char and compare again etc.

Now we have one byte we can get another one by shift the previous request by one on the left : `bbbbbbTHIS_IS_A_SECRET_COOKIE`. He now have six `b` and we also now the `T`, so we have one char unknow. We build a new P'<sub>0</sub> = C<sub>0</sub> ⊕ C<sub>4</sub> ⊕ bbbbbbTX etc...

**Note**: another way with only two request is to set the first block of the plaintext and use this information for the three XOR. We don't need anymore the C² last block. C<sub>1</sub> = E<sub>k</sub>(C<sub>0</sub> ⊕ bbbbbbbT) and then P'<sub>0</sub> = C<sub>0</sub> ⊕ C<sub>4</sub> ⊕ bbbbbbbX. He also need to compare C'<sub>0</sub> and C<sub>1</sub>.
This is another way to do it, you can notice in the PoC i code the two possibilities :)

We can now retrieve all the char !

### Launch

```
python BEAST-poc.py
```

[![asciicast](https://asciinema.org/a/40094.png)](https://asciinema.org/a/40094)

#### Attack

An attacker cannot use HTTP protocol because the first block will be field with `GET / HTTP/1.1\r\n`.

> ... cannot control the first few bytes of each request because they are always
set as a fixed string such as GET /, POST /, etc. Instead he can use [socket](https://en.wikipedia.org/wiki/Network_socket).

He also need to inject some javascript into a malicious page. The victim need to be connected to this page and stay during unitl the attack is done.
This is a chosen-plaintext attack so the attacker can send through the javascript code every plaintext he wants and intercept the result with a Man in The Middle. This diagram of the attack :

![beast](https://user-images.githubusercontent.com/5891788/52014211-41b1f780-24df-11e9-9af3-c0ae82f8df7e.png)

This attack need a important conditions to be successfull (TLS1.0 or inferior, CBC cipher mode, MiTM, malicious javascript). But Thai Duong and Juliano Rizzo proove it can be possible and the demontrate there exploit by stealing cookie on [Paypal](https://www.youtube.com/watch?v=BTqAIDVUvrU) webiste.

Everythings is now fix and this attack has little probability of being realized.

## Contributor

[mpgn](https://github.com/mpgn) 

### Licences

[licence MIT](https://github.com/mpgn/BEAST-PoC/blob/master/LICENSE)

### References

* http://netifera.com/research/beast/beast_DRAFT_0621.pdf
* http://www.bortzmeyer.org/beast-tls.html
* http://fr.slideshare.net/danrlde/20120418-luedtke-ssltlscbcbeast
* http://crypto.stackexchange.com/questions/5094/is-aes-in-cbc-mode-secure-if-a-known-and-or-fixed-iv-is-used
* http://security.stackexchange.com/questions/18505/is-beast-really-fixed-in-all-modern-browsers
* https://defuse.ca/cbcmodeiv.htm
* http://stackoverflow.com/questions/22644392/chrome-websockets-cors-policy
