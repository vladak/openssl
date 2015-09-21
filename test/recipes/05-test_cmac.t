#! /usr/bin/perl

use OpenSSL::Test::Simple;

simple_test("test_cmac", "cmactest", "cmac");
