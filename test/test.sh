#!/bin/sh
# $Id: Makefile 1827 2011-11-15 17:05:02Z umaxx $ */

# Copyright (c) 2011 Jörg Zinke <info@salbnet.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

RESULT="test/result.tmp"

test_assert() {
    while read line; do
        fgrep -q "$line" $RESULT || { echo -e "failed to match:\n $line"; exit 1; }
    done < $1 
    rm $RESULT
    echo "ok."
}

echo -n "test case 1: http/1.0 common log single request... "
./servload http://www.salbnet.org:80/ test/test1.log > $RESULT 2> /dev/null
test_assert test/result1.txt

echo -n "test case 2: http/1.1 common log... "
./servload http://www.salbnet.org/ test/test2.log > $RESULT 2> /dev/null
test_assert test/result2.txt

echo -n "test case 3: http/1.1 common log fast... "
./servload http://www.salbnet.org/ test/test2.log fast > $RESULT 2> /dev/null
test_assert test/result3.txt

echo -n "test case 4: http/1.1 common log multiply... "
./servload http://www.salbnet.org/ test/test2.log multiply 3 > $RESULT 2> /dev/null
test_assert test/result4.txt

echo -n "test case 5: http/1.1 common log peak... "
./servload http://www.salbnet.org/ test/test2.log peak 3 > $RESULT 2> /dev/null
test_assert test/result5.txt

echo -n "test case 6: http/1.1 common log score... "
./servload http://www.salbnet.org/ test/test2.log score 3 > $RESULT 2> /dev/null
test_assert test/result6.txt

echo -n "test case 7: http/1.1 common log heise.de... "
./servload http://www.heise.de/ test/test3.log > $RESULT 2> /dev/null
test_assert test/result7.txt

# todo: dns test cases
