# King's Ransom 2
`Kings Ransom 2`  was the last present we got from Marco we got, and it turned out to be a real present.

# Setup
On Kings Ransom 2 we started with having Remote Code Execution (RCE), as this was the goal of the previous Kings Ransom challenge. 
The exploit used in Kings Ransom (1) and described in the previous writeup could also be used in Kings Ransom 2 to gain RCE.

# Encryption
The system's `bank` folder contained an encrypted flag file, called `flag.txt.enc`.

Its content look like this:

```
U2FsdGVkX18vx37VNCLaVLr8fU1bgJ98rnMiMLVX6V9G4navE7/qwEKLeRHUwJy5
rpeDYOfEh8QwnUHDWFsT/PletJcpM8c3solydHbEazIOlsXGMhJ8N5oawMRinHm2
N99ZrsmPuw7Ie7g5EqeV/ebnddS2p782tyyIYfyIHktJYA+eeFafTwnqzAjCFveo
```

Additionally there was a shell script documenting how the flag was encrypted:

```bash
#!/bin/bash
for f in /challenge/bank/*;do
openssl enc -aes-256-cbc -a -pbkdf2 -in "$f" -out "$f".enc -k $(cat /challenge/key)
dd if=/dev/urandom of=$f bs=1024 count=10
rm "$f"
done
for f in /challenge/{gen,key,exploit.bin}; do
dd if=/dev/urandom of=$f bs=1024 count=10
rm $f
done
```

# Key Recovery
As this was some military grade encryption, we somehow had to recover the key. 
We had the idea that the key might still be somewhere in RAM. 
To confirm that theory we wanted to find out how the challenge was setup.

## Entrypoint
While digging through the system's file system, we found that the root directory contained a `entrypoint.sh` script:
```bash
#!/bin/sh 
echo "Starting up Service on tcp:${SERVICE_HOST}:${SERVICE_PORT}"
mkdir -p /challenge/bank
echo "Your King is in another castle" > /challenge/flag1.txt
echo ${FLAG} > /challenge/bank/flag2.txt

env -i /challenge/runner  &

while read line
do
    echo "Nothing here"
done < "${1:-/dev/stdin}"

```
This told us that the challenge was likely running within a container and the flag was passed into that container via a FLAG environment variable.

# Getting the Flag
By using the advanced hacking tool `cat` we were able to read out the environment of the first process launched within the container's namespace:

```bash
cat /proc/1/environ
```

This command returned the following string,
 
 ```
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00OSTNAME=347c61683fca\x00CM_OUTER_IP=3.137.158.115\x00CM_OUTER_PORT_BASE=30603\x00ERVICE_HOST=3.137.158.115\x00ERVICE_PORT=30603\x00EED=1341334715120241805\x00LAG=flag{golf753802charlie2:GOX1Hju_fB6_haNikukzOVmL_a3H_wBwDPjZjsh4-PrDitBQ41QICn4Tuzi9lDqDoEbktbd5v_BLsRKyu8PxWVo}\x00OME=/home/challenge\x00
```
which contained the flag `flag{golf753802charlie2:GOX1Hju_fB6_haNikukzOVmL_a3H_wBwDPjZjsh4-PrDitBQ41QICn4Tuzi9lDqDoEbktbd5v_BLsRKyu8PxWVo}`.

This seems to be an uninteded solution since we bypassed the encryption entirely. 
However, we seem to have hacked the simulation and therefore submitted the flag without a feeling of guilt.