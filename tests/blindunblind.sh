#!/bin/bash
set -e

MYSECKEY=./tests/testdata/foo-bar.com_secret_openpgp.txt
MYPUBKEY=./tests/testdata/foo-bar.com_public_openpgp.txt
CASECKEY=./tests/testdata/foobar-bar.com_secret_2048.txt
CAPUBKEY=./tests/testdata/foobar-bar.com_public_2048.txt

cd ..
./nym-prepare.py "Foo Bar" $MYSECKEY > nymhash.bin

./blind.py random.txt $CAPUBKEY <nymhash.bin >blindmessage.asc

./sign.py $CASECKEY <blindmessage.asc >blindsignature.asc

./unblind.py random.txt $CAPUBKEY <blindsignature.asc >signature.asc

gpg --verify signature.asc nymhash.bin

./nym-build.py "Foo_Bar.nym" signature.asc > signednym.asc

./nym-verify.py signednym.asc $CAPUBKEY

rm nymhash.bin
rm blindmessage.asc
rm random.txt
rm blindsignature.asc
rm signature.asc
rm Foo_Bar.nym
rm signednym.asc
cd -