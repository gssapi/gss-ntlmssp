#!/bin/sh

export NTLM_USER_FILE="examples/test_user_file3.txt"
export TEST_USER_NAME="TESTDOM\\testuser"
./ntlmssptest
