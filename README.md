# XCPUKey-Miner
A Xbox 360 CPU key brute forcer and public miner, built using C, uses both CPU and OpenCL
Currently working on the front end of the pool and OpenCL varient, so please wait until I finish :)

What speeds are we looking at ?
Well on a raspberry pi version 2 b model, I got 86k hashes per second, expect larger hashes when
I get the cpu version done.

# Linux
To build on linux you need the following installed, on Ubuntu version do the following :
sudo apt-get install build-essential libjson0 libjson-dev libssl libssl-dev curl libcurl-openssl-dev

to make just run : make

# Windows
Coming soon.

#Usage 
cpu-gen [!keyvault_location] [!algo_type] [!serial_number] [thread_count] [start_seed]

NOTE : Each argument with a ! in it, needs to be set, without ! is optional.
[keyvault_location] - The filepath to the ENCRYPTED keyvault.
[algo_type] - The also to use, can be 1, 2, 3, 4
[serial_number] - Your console serial number, 12 numbers.
[thread_count] - The number of cpu threads to use, default: num of cpu cores.
[starting_seed] - The seed to start with, must be 16 bytes long.

Algo 1 Random + Hash
Algo 2 Random + Increment
Algo 3 Start Seed + Hash
Algo 4 Start Seed + Increment
