#!/bin/sh

EXAMPLES=$(dirname "$0")/../examples

export NTLMSSP_TEST_DEBUG="tests-trace-2.log"

export NTLM_USER_FILE="${EXAMPLES}/test_user_file3.txt"
export TEST_USER_NAME="TESTDOM\\testuser"
./ntlmssptest

if [ ! -f "tests-trace-2.log" ]; then
  echo "Debug trace file not found!"
  exit -1
fi
