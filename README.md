# BIP38

A Java implementation of the BIP-0038 Draft: [Passphrase-protected private key](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) for Bitcoin.

## Usage

`BIP38.encryptEC(password, lot, sequence)` generates an encrypted key starting with 6P. 
If you don't care about lot/sequence (if you don't know what they are, you don't care),
   just use -1 for the lot. That will cause those parameters to be ignored.

   `BIP38.decrypt(password, encrypted key)` yields the decrypted get.

   Currently only encryptEC and decryptEC have been tested (and barely).

## Example:

   Key generation:

   `encrypt("hello", -1, -1)`

   might produce 

   `6PgMiWeAFVWrLUohAiM5YdtGjaZwaHGoLH6oaUysnkt6XuQS7VXcRmmuWs`

   Decryption:

   `decrypt(hello, "6PgMiWeAFVWrLUohAiM5YdtGjaZwaHGoLH6oaUysnkt6XuQS7VXcRmmuWs")`

   will result in

   `5JtA62jW9F38PU4T116PE6rfmz3b2X2auLWWHKfCyzzWdqEP8qB`

   which corresponds to address

   `1hE5eAbTrqEJZHLP8J1Eje5HHJU9aHVrj`

## To do

   * implement the remaining functionality from the spec (e.g. generate compressed keys)
  * write some tests.
  * make the code cleaner.

## Tips

  If you find this useful, tips are welcome :)

  **1EmwBbfgH7BPMoCpcFzyzgAN9Ya7jm8L1Z**

## License

  Copyright © 2014 Diego Basch

  Licensed under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)
