#! /usr/bin/env perl
# Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT data_file bldtop_dir srctop_file);

setup("test_evp");

my @configs = qw( default-and-legacy.cnf fips.cnf );
my @files = qw( evpciph.txt evpdigest.txt );
my @defltfiles = qw( evpencod.txt evpkdf.txt evppkey_kdf.txt evpmac.txt
    evppbe.txt evppkey.txt evppkey_ecc.txt evpcase.txt evpaessiv.txt
    evpccmcavs.txt );

plan tests => (scalar(@configs) * scalar(@files)) + scalar(@defltfiles);

$ENV{OPENSSL_MODULES} = bldtop_dir("providers");

foreach (@configs) {
    $ENV{OPENSSL_CONF} = srctop_file("test", $_);

    foreach my $f ( @files ) {
        ok(run(test(["evp_test", data_file("$f")])),
           "running evp_test $f");
    }
}

#TODO(3.0): As more operations are converted to providers we can move more of
#           these tests to the loop above

$ENV{OPENSSL_CONF} = srctop_file("test", "default-and-legacy.cnf");

foreach my $f ( @defltfiles ) {
    ok(run(test(["evp_test", data_file("$f")])),
       "running evp_test $f");
}
