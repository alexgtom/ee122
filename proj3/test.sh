#!/bin/bash
VERBOSE=1

echo "*** Running tests ..."

assert_pass() {
    command=$1
    if [ $VERBOSE != 0 ]; then
        echo "*** Executing '$command'"
        eval $command
    else
        eval $command > /dev/null
    fi
    rc=$?
    if [ $rc != 0 ]; then
        echo "FAIL: Expected return code to be 0 for '$command'"
        exit 1
    fi
}

assert_fail() {
    command=$1
    if [ $VERBOSE != 0 ]; then
        echo "*** Executing '$command'"
        eval $command
    else
        eval $command > /dev/null
    fi
    rc=$?
    if [ $rc == 0 ]; then
        echo "FAIL: Expected return code to be anything except 0 for '$command'"
        exit 1
    fi
}
# --------------------------------------------------
# write your tests here
# --------------------------------------------------

# sample usage
assert_fail "grep nosuchpattern /etc/passwd"
assert_pass "ls"

# dns tests
assert_fail "dig peets.com"
assert_fail "dig asdf.peets.com"
assert_pass "dig google.com"
assert_pass "ping -c 1 google.com"

# We pass all tests
echo "*** -----------------------------------------------------"
echo "*** ALL TESTS PASSED"
