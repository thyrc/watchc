#!/bin/sh
#
# Original:
# totp.sh - Shell script implementation of TOTP (RFC 6238)
#
# Copyright © 2020 Rich Felker
# Licensed under standard MIT license
#
# SPDX-License-Identifier: MIT
#
# https://github.com/richfelker/totp.sh
#
# Modified to work with plain text secrets.
#
# Usage: echo -n "secret" | watch.sh >/tmp/watch.me

t=$(($(date +%s)/30))
k="$(od -v -An -tx1 | tr -d ' \n')"

h=$(
    printf '%b' $(printf '\\x%.2x' $(
        i=0; while test $i -lt 8 ; do
            echo $(((t>>(56-8*i))&0xff))
            i=$((i+1))
        done
    )) | openssl dgst -sha1 -mac HMAC -macopt hexkey:"$k" -r | cut -d' ' -f1
)

o=$((0x${h#??????????????????????????????????????}&0xf))

while test $o -gt 0 ; do
    h=${h#??}00
    o=$((o-1))
done

h=${h%????????????????????????????????}
h=$(((0x$h & 0x7fffffff)%1000000))

printf '%.6d\n' "$h"
