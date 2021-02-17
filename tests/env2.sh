#!/bin/sh

EXAMPLES=$(dirname "$0")/../examples

export NTLM_USER_FILE="${EXAMPLES}/test_user_file3.txt"
export TEST_USER_NAME="TESTDOM\\testuser"
./ntlmssptest
