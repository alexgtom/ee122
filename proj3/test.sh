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

# % starbucks from proj specs
# % allow pings, but no other types of ICMP packets
# drop icmp any any
# pass icmp any 0
# pass icmp any 8
assert_pass "ping -c 1 google.com"

# % allow DNS packets only to Google DNS servers
# drop udp any any
# pass udp 8.8.8.8 53
# pass udp 8.8.4.4 53
assert_pass "nc -u -w1 8.8.8.8 53"
assert_pass "nc -u -w1 8.8.4.4 53"
assert_fail "nc -u -w1 8.8.4.4 10"
assert_fail "nc -u -w1 9.9.9.9 10"

# % allow only HTTP(80), HTTPS(443), and Skype(1024-65535)
# drop tcp any any
# pass tcp any 80
# pass tcp any 443
# pass tcp any 1024-65535
assert_pass "nc 8.8.8.8 80"
assert_pass "nc 8.8.8.8 443"
assert_pass "nc 8.8.8.8 1024"
assert_pass "nc 8.8.8.8 65535"
assert_pass "nc 8.8.8.8 30000"
assert_fail "nc 8.8.8.8 53"
assert_fail "nc 9.9.9.9 53"

# % punish Italy (for not having Starbucks) and MIT (for the greedy /8 address block)
# drop tcp it any
# drop tcp 18.0.0.0/8 any
assert_fail "nc 18.0.0.0 53"
assert_fail "nc 2.16.70.0 53"
assert_fail "nc 2.16.71.255 53"

# % ahem
# drop dns peets.com
# drop dns *.peets.com
assert_fail "dig peets.com"
assert_fail "dig asdf.peets.com"
assert_pass "dig google.com"

# We pass all tests
echo "*** -----------------------------------------------------"
echo "*** ALL TESTS PASSED"
