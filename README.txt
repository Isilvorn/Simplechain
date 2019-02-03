This program was written by Jason Orender (c)2019.  It represents a toy application illustrating the functionality and utility of a simple blockchain.  It was written in Python 2.7 and utilizes the "pycrypto" library for RSA and SHA256 encryption and hashing algorithms, including signature generation and verification.

To install pycrypto, ensure that python pip is installed and then type:
"pip install pycrypto"

This program consists of a single file "blockchain.py".  Within it are the definitions of three classes that define collections of data for three different object types: 1) Transactions (Trans), 2) Blocks (Block), 3) the Blockchain (Bchain).  

The transactions class encapsulates all of the data specific to one transaction, including: 
     a) the public key of the customer making the transaction
     b) the public key of the merchant making the transaction
     c) the transaction date
     d) the transaction amount
     e) the customer's signature over fields a-d
     e) the merchant's signature over fields a-e
The first four fields are given when creating an instance of the class, and the last two are calculated based on the inputs.

The blocks class incorporates an instance of the transactions class, as well as additional signature data from the miner, and a link to the previous block in the form of a calculated hash.

The blockchain class contains a list of block instances, and incorporates the means to both add blocks and verify the integrity of the blockchain. 

The program is completely self-contained and requires no input files. All test data is randomly generated at the time of execution, and a sample output is included in the file "output.txt".  To run the program, simply type:
"python blockchain.py"