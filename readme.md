# SSHram
SSHram is a simple tool for SSH private key management.

# What you need
 - A storage medium (your computer's drive, a USB key...)
 - Your SSH private key, secured by ChaCha20-Poly1305
 - SSHram's binary

# How it works
 - You plug your USB key in a trusted computer and run the SSHram binary
 - Your SSH private key is decoded and stored in a non-swappable memory area
 - A Unix named pipe is created inside the `~/.ssh/` folder in place of the key
 - If the access is confirmed, SSHram sends the private key over the named pipe

# Why it works
 - SSHram stores the decoded SSH private key in locked memory.
   This means the operating system cannot swap it out of RAM,
   and guarantees the key will never be written on drives.
 - Named pipes are virtual files serving as handles to Unix pipes.
   Because they are not actual files, everything is handled in memory,
   and the private SSH key is never written to the drive the pipe resides on.
 - Because Linux is a good operating system, most applications are compatible
   with named pipes by default, and these can be used in place of real files.

# Purpose
The goal of SSHram is to assist the user in hiding the tracks of a private key.
Some people want to use the same SSH private key on different trusted devices,
but are worried their key could be reconstructed afterwards by some evil user
(if the device is lost, stolen or stealthily accessed with bad intentions).

SSHram is meant to mitigate the most obvious attacks known to be feasible in
this scenario (data theft, sector `grep`ing, RAM cold-reading...) or if the
device holding the private key itself gets compromised.

# Limitations
The goal of SSHram is *not* to provide any kind of extra security to the user
if the target computer SSHram is executed on is not considered trustworthy.

SSH cannot be secured if the computer it runs on is not secure itself,
and SSHram (or any other SSH helper program) is useless in this case.

# Getting started
## Recommended key generation practices
 - Generate your private key offline, in a clean ramdisk, on trusted hardware
   (You could use a trusted Linux installation image booted from another USB key).
 - Generate your key using trusted cryptography. Avoid algorithms designed
   with the help of some government or including shady constants.
 - Use multiple rounds of key derivation. It helps slowing attacks down without
   turning your data into an advertisement as much as overkill crypto stength does.
```
ssh-keygen -t ed25519 -a 100
```

## Encoding a private key
Once your SSH key pair is generated, your must encode the SSH private key.
For this, run `sshram` with the `--encode` argument and follow the instructions:
```
sshram -e id_ed25519 id_ed25519.chachapoly
```

After the private key was encoded, overwrite the plain-text version and test:
```
mv id_ed25519.chachapoly id_ed25519
sshram id_ed25519
```

You can now try to connect to a server using this keypair; it will require
multiple key transmissions though, as described at SSHram's startup.

## Arguments
SSHram accepts other arguments than `--encode`, get the full list with `--help`:
```
sshram -h
```
