**Note 2016**: This is an old version of the PoC, complicated to understand. I removed a lot of useless things on the new version, this should be more focused on cryptography behind the attack.

#BEAST attack

A sample application of the **BEAST** attack with a MiTM to demonstrate the vunlerability of the protocol SSLv3, TLSv1

## How this exploit work ?

- **Server** :
It's a perfect secure server ready to make handshake with a client using the protocol SSLv3 and receive encrypted requests from the client through is handler. <br />
Class: `Server()` -  Important functions : `connection()`, `SecureTCPHandler.handle()`, `disconnect()`

- **Client** :
A sample client, can be related to a web browser. The client makes requests to a server with a cookie inside. <br />
Class: `Client(AESCipher)` -  Important functions : `connection()`, `request(...)`, `disconnect()` <br />
Example request :
```
GET / HTTP/1.1\r\nCookie: UpVP0rDn5SoHoiX9\r\n\r\n
```

- **Proxy** :
The proxy is our man in the middle, he is completely passive. He intercepts encrypted requests from the client to the server and lets the attacker alter them. He also intercepts the data from the server to the client and gets the header response status. <br />
Class: `Proxy()` -  Important functions : `ProxyTCPHandler.handle()`

- **Attacker** : He can ask to the client generate a request to a secure server with a cookie inside. In real case, it can be done by injecting some javascript into the a web page visited by the client.
He also alters client's requests regarding the proxy interception. Finally he can decipher one byte of the client's request. <br />
Class: `Beast(Client)` -  Important functions : `run()`, `alter(...)`

**Note** I don't find a way to use ssl context from Python. I use a() traditionnal encryption)[http://stackoverflow.com/a/12525165/2274530] in AES (utils/AESCipher) wit no mac and padding. Follow this [issues](https://github.com/mpgn/BEAST-exploit/issues/1)

###Exploit

The attack starts with the function `exploit.run()`.
By hypothesis the requests are encrypted  with [CBC](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29). We know that the length of the bloc are 16 bytes because it's AES.

The attacker know the construction of the packet except the secret text.

For example : `|the secret is TH|IS_IS_SECRET...|`

The attacker know the length of `the secret is ` is 14 bytes. He adds a byte to make the request 15 bytes length. (This is padding in the code).
After that he will have something like that:

`athe secret is T|HIS_IS_SECRET...|`

Now, he doesn't know only one char : T. (he will try the  256 possibilities to find the result.)

After that, a request from the client is send to a server, the proxy intercept this request and the attacker reads and remembers.
He takes the last cipher block of the request and the Ci-1 cipher block he want to decrypt.
He makes a xor operation of (athe secret is T) XOR iv XOR ci-1 and send this to the serveur.
When he will intercept the request, he checks if the cipher are the same in the first request and in the second request. If no, he will retry with an another char. Otherwise we will change the plaintext guess :

`the secret is GH|IS_IS_SECRET...|`

And he repeats the previous operation until he decrypts all bytes of the secret text.

##Run it !

Require python version `2.7.*` to launch this exploit. Then just run:
```
python BEAST.py localhost 1111
```

##Ressources
- http://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack
- https://github.com/EiNSTeiN-/chosen-plaintext
- http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
- http://www.hit.bme.hu/~buttyan/courses/EIT-SEC/abib/04-TLS/BEAST.pdf
