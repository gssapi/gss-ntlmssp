#!/bin/sh

EXAMPLES=$(dirname "$0")/../examples

export NTLM_USER_FILE="${EXAMPLES}/test_user_file2.txt"
export TEST_USER_NAME="testuser"
./ntlmssptest
