# Written by Jason Orender in Python 2.7.
# This program uses the pycrypt library version 2.6.1 (http://www.pycrypto.org/)
# available by running the installation command: "pip install pycrypt".  You may 
# have to install "python-pip" prior to running this command.

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from random import *

# The "Trans" class holds the transaction data and calculates the signatures for
# each transaction.
class Trans:
	# the constructor sets up the transaction data and signs the transaction
	def __init__(self, cust_key, merch_key, date, amount):
		self.err       = "" # explanatory variable in case an error is generated

		cust_priv_key  = cust_key
		cust_pub_key   = cust_key.publickey()
		merch_priv_key = merch_key
		merch_pub_key  = merch_key.publickey()

		self.cpubkey   = cust_pub_key.exportKey("PEM")   # FIELD #1
		self.mpubkey   = merch_pub_key.exportKey("PEM")  # FIELD #2
		self.date      = date                            # FIELD #3
		self.amount    = amount                          # FIELD #4

		# concatenating the data fields
		data           = self.cpubkey + self.mpubkey + date + "{:.2f}".format(amount)
		# hashing the concatenated data
		data_hash      = SHA256.new(data)
		# encrypting the hash with the customer's private key to sign the transaction
		self.csign     = PKCS1_v1_5.new(cust_priv_key).sign(data_hash) # FIELD #5
		# concatenating the data and the customer signature field
		d_plus_csign   = data + self.csign
		# hashing the concatenated data
		dpcsign_hash   = SHA256.new(d_plus_csign)
		# encrypting the hash with the merchant's private key to sign the transaction
		self.msign     = PKCS1_v1_5.new(merch_priv_key).sign(dpcsign_hash) # FIELD #6

	# the verify function simply checks the data integrity of a single transaction
	def verify(self):
		self.err       = ""
		cust_pub_key   = RSA.importKey(self.cpubkey)
		merch_pub_key  = RSA.importKey(self.mpubkey)

		# concatenating the data fields
		data           = self.cpubkey + self.mpubkey + self.date + "{:.2f}".format(self.amount)
		# hashing the concatenated data
		data_hash      = SHA256.new(data)
		# encrypting the hash with the customer's private key to sign the transaction
		if (PKCS1_v1_5.new(cust_pub_key).verify(data_hash, self.csign)):
			d_plus_csign = data + self.csign
			dpcsign_hash = SHA256.new(d_plus_csign)
			if (PKCS1_v1_5.new(merch_pub_key).verify(dpcsign_hash, self.msign)):
				return True
			else:
				self.err = "SIGNATURE VERIFICATION (against merchant data) FAILED for transaction"
				return False
		else:
			self.err = "SIGNATURE VERIFICATION (against customer data) FAILED for transaction"
			return False

	def show(self):
		if (self.verify()):
			validity = "valid"
		else:
			validity = "invalid"
		print self.date + "  $" + "{:.2f}".format(self.amount) + "(" + validity + ")"   

# The Block class contains all of the data used to describe each block.  It
# automatically calculates the required hashes and signatures, and has the
# capability to verify internal consistency.
class Block:
	# the constructor sets all fields according to arguments provided
	# num       = the index of the block
	# miner_key = the private key of the miner creating the block
	# trans     = the transaction fields for the block
	# prev_hash = the "bhash" of the preceding block
	def __init__(self, num, miner_key, trans, prev_hash):
		self.err    = ""          # explanatory variable in case an error is generated
		self.errnum = 0           # additional data to be passed with error
		self.seq    = num         # assign a sequence number (FIELD #7)

		# if num is zero, this is the genesis block
		if (num == 0):
			self.bhash = SHA256.new(0).hexdigest()
			prev_hash  = self.bhash 
			# creating a hash of fields 6-8, for genesis block 6 & 7 are zeroes
			block_hash = SHA256.new(prev_hash)
		else:
			self.btrans = trans # transfer the data from the transaction to this block
			# concatenate all block data into a single string
			bdata = trans.cpubkey + trans.mpubkey + trans.date + "{:.2f}".format(trans.amount) \
		    	  + trans.csign + trans.msign + str(num)
		    # the hash created from these concatenated fields will be used to link the
		    # blocks together
			self.bhash = SHA256.new(bdata).hexdigest()
			# creating a hash of fields 6-8
			block_hash = SHA256.new(trans.msign + str(num) + prev_hash)

		# for every block except the genesis block, this is the previous block's bhash
		self.phash = prev_hash # FIELD #8
		# creating a signed copy to be stored in the chain
		self.msig  = PKCS1_v1_5.new(miner_key).sign(block_hash) # FIELD #9
		self.minerpubkey = miner_key.publickey().exportKey("PEM")

	# verifies all block signatures
	def verify(self):
		self.err = ""
		mpub = RSA.importKey(self.minerpubkey)
		if (self.seq == 0):
			# verifying the genesis block via a special procedure since there is no transaction data
			zerohash   = SHA256.new(0).hexdigest()
			block_hash = SHA256.new(zerohash)
			if (not PKCS1_v1_5.new(mpub).verify(block_hash, self.msig)):
				self.err = "SIGNATURE VERIFICATION (against miner) FAILED for genesis block"
				self.errnum = 0
				return	False
		else:
			# verifying that the customer and merchant signatures check out
			if (not self.btrans.verify()):
				self.err = "TRANSACTION VERIFICATION FAILURE"
				self.errnum = self.seq
				return False 
			# concatenate all block data into a single string
			bdata = self.btrans.cpubkey + self.btrans.mpubkey + self.btrans.date \
				  + "{:.2f}".format(self.btrans.amount) + self.btrans.csign      \
				  + self.btrans.msign + str(self.seq)
			# calculate the hash to compare against the recorded hash
			test_hash = SHA256.new(bdata).hexdigest()
			if (test_hash != self.bhash):
				self.err = "INCONSISTENT HASH (between chain and data)"
				self.errnum = self.seq
				return False
			# creating a hash of fields 6-8 to test against the signature
			block_hash = SHA256.new(self.btrans.msign + str(self.seq) + self.phash)
			# test the signature to ensure the integrity of the recorded hash
			if (not PKCS1_v1_5.new(mpub).verify(block_hash, self.msig)):
				self.err = "SIGNATURE VERIFICATION (against miner data) FAILED for block #" + str(self.seq)
				self.errnum = self.seq
				return False

		# return True if all of the verification steps are complete
		return True


class Bchain:
	# the constructor creates the genesis block and signs it with a miner's private key
	def __init__(self, miner_key):
		self.err     = "" # explanatory variable in case an error is generated
		self.errnum  = 0  # additional data to be passed with error
		self.seq     = 0  # the constantly incrementing sequence number
		self.blocks  = [] # the list of blocks in the chain
		# appending the genesis block
		self.blocks.append(Block(0, miner_key, 0, 0))

	# adds a transaction block to the chain and includes the hash of the previous block's
	# data to ensure that the data is truly linked like a chain
	def add(self, trans, miner_key):
		self.err = ""
		self.seq += 1
		self.blocks.append(Block(self.seq, miner_key, trans, self.blocks[self.seq-1].bhash))

	# verifies the integrity of the chain and triggers verification checks at every
	# subordinate level (block and then transaction levels) by cascading verification checks
	def verify(self):
		self.err = ""
		for i in range(self.seq+1):
			if (i == 0):
				if (not self.blocks[0].verify()):
					self.err = "BLOCK VERIFICATION FAILURE (genesis block)"
					self.errnum = 0
					return False
			else:
				if (self.blocks[i].phash != self.blocks[i-1].bhash):
					self.err = "INCONSISTENT HASH (between blocks " + str(i) + "/" + str(i-1) + ")"
					self.errnum = i
					return False
				if (not self.blocks[i].verify()):
					self.err = "BLOCK VERIFICATION FAILURE (block #" + str(i) + ")"
					self.errnum = i
					return False
		return True

	# prints a summary of the transactions to stdout (specifying a customer public key or a
	# merchant public key will filter by that criteria, otherwise just put zeroes)
	def summary(self, cpub, mpub):
		print "Num  Customer Public Key  Merchant Public Key  Transaction   Transaction"
		print "          Excerpt              Excerpt             Date         Amount  "
		print "===  ===================  ===================  ============  ==========="
		for i in range(1,self.seq+1):
			if (((cpub == 0) and (mpub == 0)) or                             \
				((cpub == self.blocks[i].btrans.cpubkey) and (mpub == 0)) or \
				((mpub == self.blocks[i].btrans.mpubkey) and (cpub == 0)) or \
				((mpub == self.blocks[i].btrans.mpubkey) and                 \
				 (cpub == self.blocks[i].btrans.cpubkey))):
				print " " + "{:0>2d}".format(i),
				print "  " + self.blocks[i].btrans.cpubkey[100:117],
				print "   " + self.blocks[i].btrans.mpubkey[100:117],
				print "   " + self.blocks[i].btrans.date,
				print "    $" + "{:.2f}".format(self.blocks[i].btrans.amount)


# The following is a simple implementation of the merchant/customer blockchain with
# a single miner.

# Setting up the sample merchant and customer RSA encryption keys
print "************************************************"
print "*          Setting up sample data              *"
print "************************************************"
print 
print "Generating merchant keys...",
merch_keys = []
for i in range(2):
	print str(i+1) + " ",
	merch_keys.append(RSA.generate(2048))
print "Done."

print "Generating customer keys...",
cust_keys = []
for i in range(5):
	print str(i+1) + " ",
	cust_keys.append(RSA.generate(2048))
print "Done."

print "Generating miner key...",
miner_key  = RSA.generate(2048)
print "Done."

print "Generating sample transactions:"
# Generating 25 sample transactions
transactions = []
for i in range(25):
	merch = randint(1,2)
	cust  = randint(1,5)
	day   = "{:0>2d}".format(randint(1,28))
	month = "{:0>2d}".format(randint(1,12))
	year  = "{:0>2d}".format(randint(2015,2018))
	date  = month + "/" + day + "/" + year
	amount = uniform(0,100)
	print "     " + "{:0>2d}".format(i+1) + ": " + "Merch#" + str(merch) + " /",
	print "Cust#" + str(cust) + "  " + date + "  $" + "{:.2f}".format(amount)
	transactions.append(Trans(cust_keys[cust-1], merch_keys[merch-1], date, amount))
	#print "                          ",
	#transactions[i].show()

print "Done."
print

print 
print "************************************************"
print "*           Generating blockchain              *"
print "************************************************"
print
# creating the chain (genesis block is automatically created via the constructor)
print "Creating empty blockchain...",
mychain = Bchain(miner_key)
print "Done."

# adding transactions to the blockchain
print "Adding generated transactions...",
for i in range(25):
	mychain.add(transactions[i], miner_key)
print "Done."

# verifying integrity of the blockchain created
print "Verifying integrity of generated blockchain...",
if (mychain.verify()):
	print "blockchain is valid."
else:
	print "blockchain is INVALID."
	print "!!! " + mychain.err
	if (mychain.err[:26] == "BLOCK VERIFICATION FAILURE"):
		print "!!! ==>" + mychain.blocks[mychain.errnum].err
		if (mychain.blocks[mychain.errnum].err == "TRANSACTION VERIFICATION FAILURE"):
			print "!!! ====>" + mychain.blocks[mychain.errnum].btrans.err
	print "***TERMINATING PROGRAM.***"
	exit()

print 
print "************************************************"
print "*             Testing blockchain               *"
print "************************************************"
print
print "Unaltered summary:"
mychain.summary(0,0)
print
print "Changing a transaction amount in block #10 (incrementing by $10)...",
mychain.blocks[10].btrans.amount += 10
print "Done."
print
print "Altered summary:"
mychain.summary(0,0)
print
print "Now running the verification procedure again..."
if (mychain.verify()):
	print "blockchain is valid."
else:
	print "blockchain is INVALID."
	print "!!! " + mychain.err
	if (mychain.err[:26] == "BLOCK VERIFICATION FAILURE"):
		print "!!! ==>" + mychain.blocks[mychain.errnum].err
		if (mychain.blocks[mychain.errnum].err == "TRANSACTION VERIFICATION FAILURE"):
			print "!!! ====>" + mychain.blocks[mychain.errnum].btrans.err
print
print "Demonstrating how to search for transactions by public key:"
print
print "All transactions by Customer #3:"
print
mychain.summary(cust_keys[2].publickey().exportKey("PEM"),0)
print
print "All transactions by Merchant #2:"
print
mychain.summary(0,merch_keys[1].publickey().exportKey("PEM"))
print
print "Demonstration complete."

