#!/bin/bash

# Adapted from SLAE32 Course

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm
if [ $? -ne 0 ]
then
        echo '[x] Could not assemble with Nasm ...'
        exit 1
fi

echo '[+] Linking ...'
ld -o $1 $1.o
if [ $? -ne 0 ]
then
        echo '[x] Could not link object file ...'
        exit 2
fi

echo '[+] Done!'

exit 0