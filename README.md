# XCPUKey-Miner
A Xbox 360 CPU key brute forcer and public miner, built using C, uses CPU raw cycles to crack/brute key and faster decryption.
Currently working on the front end of a private cloud of gpus to crack cpu keys and retreive keyvaults, it will be a paid service!

What speeds are we looking at ?
Well on a raspberry pi version 2 b model, I got 86k hashes per second.

How does this generate a key ?
essentialy the main algo is md5, it just hashes a random start seed over and over.
# Linux
To build on linux you need the following installed, on Ubuntu version do the following :
sudo apt-get install build-essential libssl libssl-dev

to make just run : make

# Windows
Coming soon.

#Usage 
cpu-gen [!keyvault_location] [!serial_number] [thread_count]

NOTE : Each argument with a ! in it, needs to be set, without ! is optional.
[keyvault_location] - The filepath to the ENCRYPTED keyvault.
[serial_number] - Your console serial number, 12 numbers.
[thread_count] - The number of cpu threads to use, default: num of cpu cores.