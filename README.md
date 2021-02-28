# XCPUKey-Miner
A Xbox 360 CPU key brute forcer and public miner, built using C, uses CPU raw cycles to crack/brute key and faster decryption.
Currently working on the front end of a private cloud of gpus to crack cpu keys and retreive keyvaults, maybe even a public pool two :P
New HMAC_SHA1 method, we do not use OPENSSL any more, every piece of the algo is provided in the source code and not through external librarys other than pthreads

What speeds are we looking at ?
On my intel i5 (unknown model) laptop in ubuntu 2004 windows subsystem I got around 20k hashes per second.
on my intel i9 9900k I got (ubuntu): 152,844 keys per second. 

How does this generate a key ?
essentialy the main algo is increment, it shares a key between all threads (each different to the last but within a uint64_t, they do not overlap either!) then increments the key on that thread.
# Linux
To build on linux you need the following installed, on Ubuntu version do the following :
sudo apt-get install build-essential pthreads

to make just run : make

# Windows
Coming soon.

#Usage 
cpu-gen [!keyvault_location] [!serial_number] [thread_count]

NOTE : Each argument with a ! in it, needs to be set, without ! is optional.
[keyvault_location] - The filepath to the ENCRYPTED keyvault.
[serial_number] - Your console serial number, 12 numbers.
[thread_count] - The number of cpu threads to use, default: num of cpu cores.